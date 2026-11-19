"""Version-one LAN API. All target access enters the explicit job action."""

import asyncio
import re
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import asdict
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, model_validator
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..config import Settings
from ..core.classify import classify_input, normalize_entry_url
from ..core.errors import FxfetchError
from ..core.lan import client_allowed
from ..core.qr import decode_image
from ..core.tls_policy import web_tls_policy
from ..icon_search.service import IconSearchService, saved_candidates
from ..model_settings import ModelSettingsService
from ..security import contained_path, password_matches, token_hash
from ..service import JobService
from ..store import Store
from .malshare_service import SampleResponse, SampleService
from .malshare_worker import SampleProvider


class BoundaryMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings, store: Store, jobs: JobService):
        self.app, self.settings, self.store = app, settings, store
        self.jobs = jobs
        self.upload_busy = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        peer = scope.get("client")
        if not client_allowed(peer[0] if peer else None, self.settings.allowed_networks):
            await JSONResponse({"error": {"code": "lan_access_only"}}, status_code=403)(scope, receive, send)
            return
        headers = {key.decode().lower(): value.decode("latin-1") for key, value in scope["headers"]}
        host = headers.get("host", "").lower()
        if host not in self.settings.allowed_hosts:
            await JSONResponse({"error": {"code": "invalid_host"}}, status_code=400)(scope, receive, send)
            return
        if scope["method"] not in ("GET", "HEAD", "OPTIONS"):
            if headers.get("origin") != f"{scope['scheme']}://{host}":
                await JSONResponse({"error": {"code": "invalid_origin"}}, status_code=403)(
                    scope, receive, send
                )
                return
        image_upload = scope["path"] in ("/api/qr-images", "/api/icon-searches", "/api/icon-recognitions")
        maximum = self.settings.limits.max_upload_bytes if image_upload else 64 * 1024
        try:
            if int(headers.get("content-length", "0")) > maximum:
                raise ValueError
        except ValueError:
            await JSONResponse({"error": {"code": "request_too_large"}}, status_code=413)(
                scope, receive, send
            )
            return
        # Authenticate before multipart parsing/spooling, not only inside the endpoint.
        current = None
        if scope["path"].startswith("/api/") and scope["path"] not in ("/api/login", "/api/session"):
            cookie = SimpleCookie()
            try:
                cookie.load(headers.get("cookie", ""))
                token = cookie["fxfetch_session"].value if "fxfetch_session" in cookie else ""
            except CookieError:
                token = ""
            current = await run_in_threadpool(self.store.session, token_hash(token)) if token else None
            error = "authentication_required" if current is None else None
            if current and scope["method"] not in ("GET", "HEAD"):
                if not secrets.compare_digest(headers.get("x-csrf-token", ""), current["csrf"]):
                    error = "invalid_csrf"
            if error:
                await JSONResponse({"detail": error}, status_code=401 if current is None else 403)(
                    scope, receive, send
                )
                return
        uploading = image_upload and scope["method"] == "POST"
        if uploading:
            if self.upload_busy:
                await JSONResponse({"detail": "decoder_busy"}, status_code=429)(scope, receive, send)
                return
            self.upload_busy = True
            try:
                buffered = bytearray()
                deadline = time.monotonic() + 30
                while True:
                    message = await asyncio.wait_for(
                        receive(), timeout=max(0.01, deadline - time.monotonic())
                    )
                    if message["type"] == "http.disconnect":
                        raise HTTPException(400, detail="upload_disconnected")
                    chunk = message.get("body", b"")
                    if len(buffered) + len(chunk) > maximum:
                        raise HTTPException(413, detail="request_too_large")
                    buffered.extend(chunk)
                    if not message.get("more_body", False):
                        break
                original_receive = receive
                delivered = False

                async def replay_receive() -> Message:
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": bytes(buffered), "more_body": False}
                    return await original_receive()

                receive = replay_receive
            except (HTTPException, TimeoutError) as exc:
                self.upload_busy = False
                code = str(exc.detail) if isinstance(exc, HTTPException) else "upload_timeout"
                status = exc.status_code if isinstance(exc, HTTPException) else 408
                await JSONResponse({"error": {"code": code}}, status_code=status)(scope, receive, send)
                return
        size = 0
        started = False

        async def bounded_receive() -> Message:
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > maximum:
                raise HTTPException(413, detail="request_too_large")
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                # FastAPI's multipart parser can translate a receive exception to 400.
                if size > maximum:
                    message["status"] = 413
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self'; "
                        b"img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                    ),
                ]
                message["headers"] = list(message.get("headers", [])) + extra
            await send(message)

        retained = None
        download = re.fullmatch(
            r"/api/jobs/([0-9a-f]{32})/(?:data-package|artifacts/[^/]+|rejected-files/[^/]+|analyses/[^/]+/report\.zip)",
            scope["path"],
        )
        if download and current and scope["method"] in ("GET", "HEAD"):
            try:
                await run_in_threadpool(self.jobs.retain_download, current["id"], download[1])
                retained = download[1]
            except FxfetchError:
                await JSONResponse({"detail": "not_found"}, status_code=404)(scope, receive, send)
                return
        try:
            await self.app(scope, bounded_receive, guarded_send)
        except HTTPException as exc:
            if started:
                raise
            await JSONResponse({"error": {"code": str(exc.detail)}}, status_code=exc.status_code)(
                scope, receive, send
            )
        finally:
            if retained:
                self.jobs.release_download(retained)
            if uploading:
                self.upload_busy = False


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(StrictModel):
    password: str = Field(min_length=1, max_length=1024)


class TLSInput(StrictModel):
    tls_policy: Literal['auto', 'strict'] = 'auto'
    ignore_tls_errors: StrictBool | None = None

    @model_validator(mode='after')
    def validate_tls_choice(self):
        self.tls_policy = web_tls_policy({key: getattr(self, key) for key in self.model_fields_set
                                         if key in {'tls_policy', 'ignore_tls_errors'}})
        return self


class JobInput(TLSInput):
    gemini_select: StrictBool = False
    url: str | None = Field(default=None, max_length=8192)
    image_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    candidate_id: str | None = Field(default=None, max_length=80)


class PreviewInput(StrictModel):
    url: str = Field(min_length=1, max_length=8192)


class BuildInput(StrictModel):
    candidate_id: str = Field(min_length=1, max_length=80)


class ContinuationInput(TLSInput):
    candidate_id: str = Field(min_length=1, max_length=80)


class EmptyInput(StrictModel):
    pass


class ModelSelectionInput(StrictModel):
    model: str = Field(min_length=1, max_length=200)
    list_token: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_-]+$')


class NameSearchInput(StrictModel):
    name: StrictStr = Field(min_length=1, max_length=100)
    recognition_id: StrictStr | None = Field(default=None, min_length=32, max_length=32,
                                            pattern=r'^[0-9a-f]{32}$')


def create_app(settings: Settings, *, service: JobService | None = None) -> FastAPI:
    jobs = service or JobService(settings)
    icons = IconSearchService(jobs.store.root)
    samples = SampleService(icons)
    models = ModelSettingsService(jobs.store.root)
    decode_lock = asyncio.Lock()
    attempts: dict[str, deque[float]] = defaultdict(deque)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        jobs.start()
        samples.recover()
        icons.start()
        try:
            yield
        finally:
            samples.close()
            await run_in_threadpool(icons.close)
            await run_in_threadpool(jobs.close)

    app = FastAPI(
        title="fxfetch", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.service = jobs
    app.state.icon_search = icons
    app.state.malshare = samples
    app.state.model_settings = models
    app.add_middleware(BoundaryMiddleware, settings=settings, store=jobs.store, jobs=jobs)

    @app.exception_handler(FxfetchError)
    async def domain_error(request: Request, exc: FxfetchError):
        status = (
            404
            if exc.code == "not_found"
            else 409
            if exc.code
            in {
                "idempotency_conflict",
                "queue_full",
                "image_queue_full",
                "invalid_build_source",
                "invalid_continuation",
                "candidate_already_selected",
                "continuation_active",
                "continuation_limit",
                "continuation_cycle",
                "analysis_active",
                "analysis_source_unavailable",
                "analysis_queue_full",
                "analysis_limit",
                "malshare_busy",
                "malshare_lookup_required",
                "bazaar_busy",
                "bazaar_lookup_required",
            }
            else 429
            if exc.code in {"malshare_daily_limit", "malshare_storage_limit", "bazaar_daily_limit", "bazaar_storage_limit"}
            else 503
            if exc.code in {"build_unavailable", "analysis_unavailable", "malshare_unconfigured", "bazaar_unconfigured"}
            else 400
        )
        detail: dict = {"code": exc.code, "message": exc.message}
        upstream_status = getattr(exc, 'http_status', None)
        if type(upstream_status) is int and 100 <= upstream_status <= 599:
            detail['http_status'] = upstream_status
        return JSONResponse({"error": detail}, status_code=status)

    async def session(request: Request) -> dict:
        token = request.cookies.get("fxfetch_session", "")
        item = await run_in_threadpool(jobs.store.session, token_hash(token)) if token else None
        if item is None:
            raise HTTPException(401, detail="authentication_required")
        if request.method not in ("GET", "HEAD"):
            if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), item["csrf"]):
                raise HTTPException(403, detail="invalid_csrf")
        return item

    def idem(value: str | None) -> str:
        if value is None or not 8 <= len(value) <= 128 or not value.isascii():
            raise HTTPException(400, detail="idempotency_key_required")
        return value

    @app.get("/api/session")
    async def get_session(request: Request):
        token = request.cookies.get("fxfetch_session", "")
        value = await run_in_threadpool(jobs.store.session, token_hash(token)) if token else None
        return {
            "authenticated": bool(value),
            "csrf_token": value["csrf"] if value else None,
            "expires": value["expires"] if value else None,
        }

    @app.post("/api/login")
    async def login(value: Login, request: Request):
        address = request.client.host if request.client else "unknown"
        now = time.monotonic()
        if len(attempts) > 1024:
            attempts.clear()
        queue = attempts[address]
        while queue and queue[0] < now - 60:
            queue.popleft()
        if len(queue) >= 5:
            raise HTTPException(429, detail="login_rate_limited")
        queue.append(now)
        valid = await run_in_threadpool(password_matches, value.password, settings.password_hash)
        if not valid:
            raise HTTPException(401, detail="invalid_credentials")
        token = secrets.token_urlsafe(32)
        value_session = await run_in_threadpool(
            jobs.store.new_session, token_hash(token), settings.session_seconds
        )
        response = JSONResponse(
            {"authenticated": True, "csrf_token": value_session["csrf"], "expires": value_session["expires"]}
        )
        response.set_cookie(
            "fxfetch_session",
            token,
            max_age=settings.session_seconds,
            httponly=True,
            secure=settings.secure_cookie,
            samesite="strict",
            path="/",
        )
        return response

    @app.post("/api/logout")
    async def logout(current: Annotated[dict, Depends(session)]):
        await run_in_threadpool(jobs.store.logout, current["id"])
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("fxfetch_session", path="/")
        return response

    @app.get("/api/capabilities")
    async def capabilities(current: Annotated[dict, Depends(session)]):
        value = await run_in_threadpool(jobs.capabilities)
        value['icon_search'] = await run_in_threadpool(icons.capability)
        return value

    @app.get('/api/model-settings')
    async def model_settings(current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(models.current)

    @app.post('/api/model-settings/refresh')
    async def refresh_models(value: EmptyInput, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(models.refresh, current['id'])

    @app.post('/api/model-settings')
    async def select_model(value: ModelSelectionInput, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(models.select, current['id'], value.model, value.list_token)

    @app.post('/api/icon-searches', status_code=202)
    @app.post('/api/icon-recognitions', status_code=202)
    async def icon_search(
        request: Request, current: Annotated[dict, Depends(session)], file: Annotated[UploadFile, File()],
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        try:
            key = idem(idempotency_key)
            data = await file.read(settings.limits.max_image_bytes + 1)
            if len(data) > settings.limits.max_image_bytes:
                raise HTTPException(413, detail='image_too_large')
            submit = icons.submit_recognition if request.url.path == '/api/icon-recognitions' else icons.submit
            return await run_in_threadpool(submit, current['id'], key, data)
        finally:
            await file.close()

    @app.post('/api/name-searches', status_code=202)
    async def name_search(value: NameSearchInput, current: Annotated[dict, Depends(session)],
                          idempotency_key: Annotated[str | None, Header()] = None):
        return await run_in_threadpool(icons.submit_name, current['id'], idem(idempotency_key),
                                       value.name, value.recognition_id)

    @app.get('/api/icon-searches/{identifier}')
    async def icon_result(identifier: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(samples.result, current['id'], identifier)

    @app.get('/api/icon-searches/{identifier}/candidates/{candidate}/{provider}/file')
    async def sample_file(identifier: str, candidate: str, provider: SampleProvider,
                          current: Annotated[dict, Depends(session)]):
        return SampleResponse(samples, current['id'], identifier, candidate, provider)

    @app.post('/api/icon-searches/{identifier}/candidates/{candidate}/{provider}/{action}')
    async def sample_action(identifier: str, candidate: str, provider: SampleProvider,
                            action: Literal['lookup', 'download'], value: EmptyInput,
                            current: Annotated[dict, Depends(session)],
                            idempotency_key: Annotated[str | None, Header()] = None):
        return await run_in_threadpool(samples.act, current['id'], identifier, candidate,
                                       action, idem(idempotency_key), provider)

    @app.get('/api/icon-searches/{identifier}/image/{kind}')
    async def icon_image(identifier: str, kind: Literal['preview', 'icon'],
                         current: Annotated[dict, Depends(session)]):
        # Read the small sanitized JPEG under the same lock as expiry; no FileResponse race.
        def read_image():
            with icons.lock:
                icons.get(current['id'], identifier)
                path = contained_path(icons.root, f'icon-searches/{identifier}/{kind}.jpg')
                return path.read_bytes()
        from fastapi.responses import Response
        try:
            return Response(await run_in_threadpool(read_image), media_type='image/jpeg')
        except (OSError, ValueError):
            raise HTTPException(404, detail='not_found') from None

    @app.post('/api/icon-searches/{identifier}/cancel')
    async def icon_cancel(identifier: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(icons.cancel, current['id'], identifier)

    @app.post('/api/icon-searches/{identifier}/collect', status_code=202)
    async def icon_collect(identifier: str, value: ContinuationInput,
                           current: Annotated[dict, Depends(session)],
                           idempotency_key: Annotated[str | None, Header()] = None):
        key = idem(idempotency_key)

        def collect():
            with icons.lock:
                result = icons.get(current['id'], identifier)
                if result['finished_at'] is None or result['state'] not in ('completed', 'partial', 'cancelled'):
                    raise FxfetchError('invalid_selection', 'Search is not finished')
                if result['expires_at'] is None or result['expires_at'] <= time.time():
                    raise FxfetchError('not_found', 'Search has expired')
                selected = next((item for item in saved_candidates(result)
                                 if item['id'] == value.candidate_id), None)
                if selected is None:
                    raise FxfetchError('invalid_selection', 'Unknown candidate')
                if selected.get('category') in ('sample_index', 'sample_record'):
                    raise FxfetchError('invalid_selection', 'Sample index is a reference page, not a download entry')
                icons.validate_evidence(identifier, result)
                evidence = {'search_id': identifier, 'candidate': selected,
                            'recognition': result.get('recognition'),
                            'input_sha256': result.get('input_sha256'),
                            'icon_sha256': result.get('icon_sha256'),
                            'same_app_verified': False}
                named = result.get('mode') == 'name'
                if named:
                    evidence.update(query_name=result['query_name'],
                                    recognition_id=result.get('recognition_id'))
                images = None
                if not named or result.get('recognition_id'):
                    original, icon = icons.evidence_files(identifier, result)
                    images = (evidence, original, icon)
                return jobs.create_job(current['id'], key, {
                    'url': selected['url'], 'tls_policy': value.tls_policy,
                    'icon_search_id': identifier, 'icon_candidate_id': value.candidate_id,
                }, icon_evidence=images, name_evidence=evidence if named else None)
        return await run_in_threadpool(collect)

    @app.post("/api/preview")
    async def preview(value: PreviewInput, current: Annotated[dict, Depends(session)]):
        parsed = classify_input(normalize_entry_url(value.url))
        return {
            "kind": parsed.kind,
            "url": parsed.original,
            "request_url": parsed.request_url,
            "original_input": value.url,
            "normalized": parsed.original != value.url,
            "network_requests": 0,
        }

    @app.post("/api/qr-images")
    async def qr(current: Annotated[dict, Depends(session)], file: Annotated[UploadFile, File()]):
        # Authentication is evaluated before file content is used; ASGI enforces the multipart wire limit.
        if decode_lock.locked():
            await file.close()
            raise HTTPException(429, detail="decoder_busy")
        async with decode_lock:
            await run_in_threadpool(jobs.cleanup_images)
            directory = jobs.store.root / "images"
            directory.mkdir(exist_ok=True)
            path = directory / (secrets.token_hex(16) + ".image")
            try:
                size = 0
                with path.open("xb") as stream:
                    while data := await file.read(64 * 1024):
                        size += len(data)
                        if size > settings.limits.max_image_bytes:
                            raise HTTPException(413, detail="image_too_large")
                        stream.write(data)
                thumbnail = path.with_name(path.name + ".jpg")
                result = asdict(
                    await run_in_threadpool(decode_image, path, settings.limits, thumbnail_path=thumbnail)
                )
                if result["status"] == "invalid_image":
                    raise HTTPException(415, detail=result.get("reason_code") or "invalid_image")
                if (
                    result["status"] in ("failed", "timed_out", "limit_exceeded")
                    and result.get("reason_code") != "qr_candidates"
                ):
                    # No invalid/partial image is registered as an accepted upload.
                    raise HTTPException(422, detail=result.get("reason_code") or result["status"])
                identifier = await run_in_threadpool(
                    jobs.store.add_image,
                    current["id"],
                    str(path.relative_to(jobs.store.root)),
                    result,
                    settings.limits.image_ttl_seconds,
                    settings.limits.max_pending_images,
                )
                return {
                    "id": identifier,
                    **result,
                    "thumbnail_url": f"/api/qr-images/{identifier}/thumbnail"
                    if result.get("thumbnail_available")
                    else None,
                }
            except Exception:
                path.unlink(missing_ok=True)
                path.with_name(path.name + ".jpg").unlink(missing_ok=True)
                raise
            finally:
                await file.close()

    @app.get("/api/qr-images/{identifier}/thumbnail")
    async def thumbnail(identifier: str, current: Annotated[dict, Depends(session)]):
        value = await run_in_threadpool(jobs.store.image, current["id"], identifier)
        if not value["result"].get("thumbnail_available"):
            raise HTTPException(404, detail="thumbnail_unavailable")
        return FileResponse(contained_path(jobs.store.root, value["path"] + ".jpg"), media_type="image/jpeg")

    @app.post("/api/jobs", status_code=202)
    async def create_job(
        value: JobInput,
        current: Annotated[dict, Depends(session)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.create_job, current["id"], idem(idempotency_key), value.model_dump(exclude={'ignore_tls_errors'})
        )

    @app.delete("/api/jobs")
    async def clear_jobs(current: Annotated[dict, Depends(session)]):
        async with decode_lock:
            await run_in_threadpool(samples.clear, current['id'])
            return await run_in_threadpool(jobs.clear_jobs, current["id"])

    @app.get("/api/jobs")
    async def list_jobs(current: Annotated[dict, Depends(session)]):
        values = await run_in_threadpool(jobs.store.list_jobs, current["id"])
        return {
            "jobs": [
                {
                    "id": item["id"],
                    "state": item["state"],
                    "outcome": item["outcome"],
                    "created": item["created"],
                    "url": item["input"]["entry_url"],
                    "active_builds": item["active_builds"],
                    "active_analyses": item["active_analyses"],
                }
                for item in values
            ]
        }

    @app.get("/api/jobs/{identifier}")
    async def get_job(identifier: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.get_job, current["id"], identifier)

    @app.post("/api/jobs/{identifier}/analyses", status_code=202)
    async def create_analysis(
        identifier: str,
        current: Annotated[dict, Depends(session)],
        value: EmptyInput | None = None,
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.analysis.create, current["id"], identifier, idem(idempotency_key)
        )

    @app.get("/api/jobs/{identifier}/analyses/{analysis_id}")
    async def get_analysis(
        identifier: str, analysis_id: str, current: Annotated[dict, Depends(session)]
    ):
        return await run_in_threadpool(jobs.analysis.get, current["id"], identifier, analysis_id)

    @app.post("/api/jobs/{identifier}/analyses/{analysis_id}/cancel")
    async def cancel_analysis(
        identifier: str, analysis_id: str, current: Annotated[dict, Depends(session)]
    ):
        return await run_in_threadpool(jobs.analysis.cancel, current["id"], identifier, analysis_id)

    @app.get("/api/jobs/{identifier}/analyses/{analysis_id}/report.zip")
    async def analysis_report(
        identifier: str, analysis_id: str, current: Annotated[dict, Depends(session)]
    ):
        path, filename = await run_in_threadpool(
            jobs.analysis.report_file, current["id"], identifier, analysis_id
        )
        return FileResponse(
            path, media_type="application/zip", filename=filename,
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/jobs/{identifier}/continue", status_code=202)
    async def continue_job(
        identifier: str,
        value: ContinuationInput,
        current: Annotated[dict, Depends(session)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.continue_job, current["id"], identifier, idem(idempotency_key), value.candidate_id,
            tls_policy=value.tls_policy,
        )

    @app.post("/api/jobs/{identifier}/cancel")
    async def cancel_job(identifier: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.cancel_job, current["id"], identifier)

    @app.post("/api/jobs/{identifier}/web-apk-builds", status_code=202)
    async def build(
        identifier: str,
        value: BuildInput,
        current: Annotated[dict, Depends(session)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ):
        return await run_in_threadpool(
            jobs.create_build, current["id"], identifier, idem(idempotency_key), value.candidate_id
        )

    @app.get("/api/jobs/{identifier}/web-apk-builds/{build_id}")
    async def get_build(identifier: str, build_id: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.get_build, current["id"], identifier, build_id)

    @app.post("/api/jobs/{identifier}/web-apk-builds/{build_id}/cancel")
    async def cancel_build(identifier: str, build_id: str, current: Annotated[dict, Depends(session)]):
        return await run_in_threadpool(jobs.cancel_build, current["id"], identifier, build_id)

    @app.get("/api/jobs/{identifier}/artifacts/{artifact_id}")
    async def artifact(identifier: str, artifact_id: str, current: Annotated[dict, Depends(session)]):
        value = await run_in_threadpool(jobs.store.artifact, current["id"], identifier, artifact_id)
        path = contained_path(jobs.store.root, value["path"])
        return FileResponse(path, media_type="application/octet-stream", filename=value["filename"])

    @app.get("/api/jobs/{identifier}/rejected-files/{file_id}")
    async def rejected_file(identifier: str, file_id: str, current: Annotated[dict, Depends(session)]):
        stream, metadata = await run_in_threadpool(jobs.rejected_file, current['id'], identifier, file_id)

        def chunks():
            try:
                remaining = metadata['size']
                while remaining and (block := stream.read(min(65536, remaining))):
                    remaining -= len(block)
                    yield block
            finally:
                stream.close()

        return StreamingResponse(
            chunks(), media_type='application/octet-stream', background=BackgroundTask(stream.close),
            headers={'Cache-Control': 'no-store', 'Content-Length': str(metadata['size']),
                     'Content-Disposition': f'attachment; filename="{metadata["filename"]}"',
                     'X-Content-Type-Options': 'nosniff'},
        )

    @app.get("/api/jobs/{identifier}/data-package")
    async def data_package(identifier: str, current: Annotated[dict, Depends(session)]):
        path, filename = await run_in_threadpool(
            jobs.data_package_file, current["id"], identifier
        )
        return FileResponse(
            path,
            media_type="application/zip",
            filename=filename,
            headers={"Cache-Control": "no-store"},
        )

    static = Path(__file__).parent / "static"
    if static.is_dir():
        app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    async def index():
        return FileResponse(static / "index.html", media_type="text/html")

    return app
