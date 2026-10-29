"""Explicitly invoked, serial static collection with conservative coverage."""

from __future__ import annotations

import hashlib
import inspect
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlsplit

from .classify import classify_input
from .discovery import Candidate, discover_html, discover_manifest_file
from .download import classify_package
from .errors import FxfetchError
from .flutter_adapter import MAX_MAIN_BYTES, discover_flutter
from .http_client import MAX_EVIDENCE_HEADER_BYTES, FetchedResponse, Hop, HttpClient
from .landing_adapter import discover_landing
from .limits import Limits
from .offline import MAX_RESOURCE_BYTES, MAX_RESOURCE_TOTAL, MAX_RESOURCES, OfflineBundle, resource_references
from .page_qr import MAX_DECODE_SECONDS, MAX_IMAGE_TOTAL, MAX_IMAGES, decode_saved_image, discover_images

_DEFAULT_LIMITS = Limits()
ANDROID_UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
IPHONE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"


def metadata_reserve(limits: Limits) -> int:
    # JSON escaping may expand each observed header byte sixfold. Reserve space
    # before body writes for every permitted request plus source/index records.
    per_request = MAX_EVIDENCE_HEADER_BYTES * 6 + limits.max_url_bytes * 6 * 4 + 4096
    candidate_records = limits.max_candidates * limits.max_url_bytes * 6 * 3
    return 16 * 1024 * 1024 + limits.max_requests * per_request + candidate_records


@dataclass(frozen=True)
class Artifact:
    kind: str
    path: Path
    sha256: str
    size: int
    url: str


@dataclass(frozen=True)
class Attempt:
    chain: str
    url: str
    outcome: str | None
    reason_code: str
    coverage: str


@dataclass
class WorkflowResult:
    outcome: str
    reason_code: str
    coverage: str
    artifacts: list[Artifact] = field(default_factory=list)
    attempts: list[Attempt] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    selection_candidates: list[Candidate] = field(default_factory=list)
    hops: list[dict[str, object]] = field(default_factory=list)
    bodies: list[dict[str, object]] = field(default_factory=list)
    page_qr: dict[str, object] = field(
        default_factory=lambda: {"status": "not_started", "sources": [], "candidates": [], "gaps": []}
    )
    offline: dict[str, object] = field(default_factory=lambda: {"available": False})
    landing: dict[str, object] = field(default_factory=lambda: {"evidence": [], "gaps": []})
    collector_mode: str = "http"


class Workflow:
    def __init__(self, client: HttpClient | None = None, limits: Limits = _DEFAULT_LIMITS) -> None:
        self.client = client or HttpClient(limits)
        self.limits = limits

    def run(
        self,
        url: str,
        output_dir: Path,
        cancel: threading.Event,
        on_event: Callable[[dict[str, object]], None] | None = None,
    ) -> WorkflowResult:
        result = WorkflowResult("failed", "not_started", "not_started")
        active_chain = "android"
        active_url = url
        request_count = 0
        web_bytes = 0
        start = time.monotonic()
        resource_cache: dict[tuple[str, str], Path] = {}
        resource_failures: set[tuple[str, str]] = set()
        snapshot_network_attempted: set[tuple[str, str]] = set()
        qr_bytes = 0
        qr_decode_seconds = 0.0
        qr_image_count = 0
        last_html: tuple[Path, str, CookieJar, str, str] | None = None
        redirect_count = 0
        reported_candidates: set[tuple[str, str, str]] = set()
        discovery_visited: dict[str, set[str]] = {}

        def emit(event: str, chain: str, source: str, **details: object) -> None:
            if on_event is not None:
                on_event({"event": event, "chain": chain, "url": source, **details})

        def transport_event(event: dict[str, object], chain: str) -> None:
            nonlocal redirect_count
            if event.get("event") == "redirect":
                target = event.get("to_url")
                if isinstance(target, str) and target in discovery_visited.get(chain, set()):
                    raise FxfetchError("discovery_cycle", "Redirect revisits a collected page")
                if redirect_count >= self.limits.max_redirects:
                    raise FxfetchError("redirect_limit", "Shared task redirect budget exceeded")
                redirect_count += 1
            if on_event is not None:
                on_event({**event, "chain": chain})

        def fetch_with_events(
            chain: str, source: str, destination: Path, *, user_agent: str,
            cookie_jar: CookieJar, cancel: threading.Event, referer: str | None,
        ) -> FetchedResponse:
            # Older synthetic/injected clients remain compatible. Never retry a
            # GET after catching TypeError: that could consume a one-use entry.
            parameters = inspect.signature(self.client.fetch).parameters.values()
            supports_events = any(
                parameter.name == "on_event"
                for parameter in parameters
            )
            events_seen = False
            def forward(event: dict[str, object]) -> None:
                nonlocal events_seen
                events_seen = True
                transport_event(event, chain)
            if supports_events:
                fetched = self.client.fetch(
                    source, destination, user_agent=user_agent, cookie_jar=cookie_jar,
                    cancel=cancel, referer=referer, on_event=forward,
                )
            else:
                emit("request", chain, source)
                fetched = self.client.fetch(
                    source, destination, user_agent=user_agent, cookie_jar=cookie_jar,
                    cancel=cancel, referer=referer,
                )
            if not events_seen:
                # An injected transport has no wire-progress callback. Report
                # only the completed facts it returned, never simulated progress.
                if supports_events:
                    emit("request", chain, source)
                for left, right in zip(fetched.hops, fetched.hops[1:], strict=False):
                    transport_event({"event": "redirect", "url": left.url,
                                     "from_url": left.url, "to_url": right.url,
                                     "status": left.status, "mechanism": "http"}, chain)
                emit("response_received", chain, fetched.url, status=fetched.status,
                     content_type=fetched.headers.get("content-type", ""))
                with fetched.path.open("rb") as stream:
                    prefix = stream.read(4)
                package_stream = prefix in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
                if package_stream and 200 <= fetched.status < 300:
                    emit("download_started", chain, fetched.url, package_unverified=True,
                         received_bytes=fetched.size, total_bytes=None)
                emit("response_complete", chain, fetched.url, status=fetched.status,
                     size=fetched.size, is_package_stream=package_stream)
            return fetched

        def announce_candidates(candidates: list[Candidate], chain: str) -> None:
            for candidate in candidates:
                key = (chain, candidate.url, candidate.source_url)
                if key not in reported_candidates:
                    reported_candidates.add(key)
                    emit("download_candidate", chain, candidate.url, kind=candidate.kind,
                         label=candidate.label, source_url=candidate.source_url,
                         action=candidate.action, verified=False)

        def verify_file(fetched: FetchedResponse, chain: str) -> str | None:
            with fetched.path.open("rb") as stream:
                prefix = stream.read(4)
            if prefix in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
                emit("file_verifying", chain, fetched.url, size=fetched.size)
            return classify_package(fetched.path, self.limits)

        def hop_records(hops: tuple[Hop, ...], chain: str, first_request_id: int) -> list[dict[str, object]]:
            return [
                dict(
                    asdict(hop),
                    chain=chain,
                    request_id=first_request_id + index,
                    mode="http",
                    user_agent=ANDROID_UA if chain == "android" else IPHONE_UA,
                )
                for index, hop in enumerate(hops)
            ]

        def record_partial(path: Path, error: FxfetchError, source: str, chain: str | None = None) -> None:
            record_chain = chain or active_chain
            partial_hops = getattr(error, "hops", ())
            result.hops.extend(hop_records(partial_hops, record_chain, request_count + 1))
            partial = path.with_name(path.name + ".partial")
            if partial.is_file():
                digest = hashlib.sha256()
                with partial.open("rb") as stream:
                    while block := stream.read(65536):
                        digest.update(block)
                result.bodies.append(
                    {
                        "path": str(partial),
                        "size": partial.stat().st_size,
                        "sha256": digest.hexdigest(),
                        "hash_scope": "saved_prefix",
                        "complete": False,
                        "reason_code": error.code,
                        "url": source,
                        "chain": record_chain,
                        "request_id": request_count + max(1, len(partial_hops)),
                        "mode": "http",
                        "user_agent": ANDROID_UA if record_chain == "android" else IPHONE_UA,
                    }
                )

        def landing_fetch(
            source: str,
            referer: str,
            jar: CookieJar,
            chain: str,
            *,
            package: bool = False,
            metadata_cap: int = 1024 * 1024,
        ) -> FetchedResponse:
            """Adapter and verified mirrors share the original task's hard budgets."""
            nonlocal request_count, web_bytes, active_url
            active_url = source
            if cancel.is_set():
                raise FxfetchError("cancelled", "Collection cancelled")
            remaining_time = self.limits.chain_timeout - (time.monotonic() - start)
            remaining_requests = self.limits.max_requests - request_count
            used = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
            remaining_disk = self.limits.max_task_bytes - metadata_reserve(self.limits) - used
            metadata_limit = min(metadata_cap, MAX_MAIN_BYTES)
            if metadata_cap <= 1024 * 1024:
                metadata_limit = min(metadata_limit, self.limits.max_body_bytes)
            body_budget = min(
                self.limits.max_body_bytes if package else metadata_limit,
                self.limits.max_web_bytes - web_bytes,
                remaining_disk,
            )
            if not package:
                left, right = urlsplit(source), urlsplit(referer)
                if (left.scheme, left.hostname, left.port or (443 if left.scheme == "https" else 80)) != (
                    right.scheme,
                    right.hostname,
                    right.port or (443 if right.scheme == "https" else 80),
                ):
                    raise FxfetchError("landing_cross_origin", "Landing metadata must remain same-origin")
            if remaining_time <= 0 or remaining_requests <= 0 or remaining_disk <= 0 or body_budget <= 0:
                raise FxfetchError("workflow_limit", "Collection task budget exhausted")
            destination = output_dir / "web" / f"{request_count:04d}.landing"
            original_limits = self.client.limits
            self.client.limits = replace(
                self.limits,
                max_body_bytes=body_budget,
                max_package_bytes=min(self.limits.max_package_bytes, remaining_disk)
                if package
                else body_budget,
                max_requests=remaining_requests,
                chain_timeout=remaining_time,
                max_redirects=self.limits.max_redirects if package else 0,
            )
            try:
                try:
                    fetched = fetch_with_events(
                        chain, source,
                        destination,
                        user_agent=ANDROID_UA if chain == "android" else IPHONE_UA,
                        cookie_jar=jar,
                        cancel=cancel,
                        referer=referer,
                    )
                except FxfetchError as error:
                    record_partial(destination, error, source)
                    partial = destination.with_name(destination.name + ".partial")
                    if partial.is_file():
                        web_bytes += partial.stat().st_size
                    request_count += max(1, len(getattr(error, "hops", ())))
                    raise
            finally:
                self.client.limits = original_limits
            first_request_id = request_count + 1
            request_count += max(1, len(fetched.hops))
            result.hops.extend(hop_records(fetched.hops, chain, first_request_id))
            result.bodies.append(
                {
                    "path": str(fetched.path),
                    "size": fetched.size,
                    "sha256": fetched.sha256,
                    "hash_scope": "wire",
                    "complete": True,
                    "url": fetched.url,
                    "purpose": "landing_package" if package else "landing_metadata",
                    "chain": chain,
                    "request_id": request_count,
                    "mode": "http",
                    "user_agent": ANDROID_UA if chain == "android" else IPHONE_UA,
                }
            )
            if not package or not 200 <= fetched.status < 300:
                web_bytes += fetched.size
            if fetched.status in (401, 403, 429):
                raise FxfetchError(
                    "http_access_control", "Landing access control response", outcome="blocked"
                )
            if not 200 <= fetched.status < 300:
                raise FxfetchError("http_status", "Landing HTTP failure")
            return fetched

        def verify_mirrors(choices: list[Candidate], source: str, jar: CookieJar, chain: str) -> None:
            """Only adapter-proven equivalent mirrors may be visited in order."""
            nonlocal web_bytes
            if not 1 <= len(choices) <= 4:
                raise FxfetchError("candidate_limit", "Verified mirror budget exceeded")
            retryable = {
                "network_timeout",
                # A node can close or fail its TLS handshake without presenting
                # an invalid certificate. Another explicitly declared mirror is
                # still checked with normal TLS; certificate failures stay fatal.
                "tls_handshake_failed",
                "transfer_failed",
                "dns_failed",
                "dns_timeout",
                "http_status",
                "candidate_not_package",
                "length_mismatch",
            }
            for candidate in choices:
                try:
                    fetched = landing_fetch(candidate.url, source, jar, chain, package=True)
                    package = verify_file(fetched, chain)
                    if package is None:
                        web_bytes += fetched.size
                        with fetched.path.open("rb") as stream:
                            prefix = stream.read(65536)
                        if "html" in fetched.headers.get(
                            "content-type", ""
                        ).lower() or prefix.lstrip().startswith(b"<"):
                            if (
                                "challenge_detected"
                                in discover_html(
                                    prefix, fetched.url, self.limits.max_candidates,
                                    content_type=fetched.headers.get("content-type"),
                                ).gaps
                            ):
                                raise FxfetchError(
                                    "challenge_detected",
                                    "Mirror returned a challenge page",
                                    outcome="blocked",
                                )
                        raise FxfetchError(
                            "candidate_not_package", "Mirror did not return the requested package"
                        )
                    if package != ("apk" if chain == "android" else "ipa"):
                        raise FxfetchError(
                            "wrong_package_platform", "Mirror returned the wrong package platform"
                        )
                except FxfetchError as error:
                    result.attempts.append(
                        Attempt(chain, candidate.url, error.outcome, error.code, "partial")
                    )
                    if error.outcome == "blocked" or error.code not in retryable:
                        raise
                    continue
                artifacts_dir = output_dir / "artifacts"
                artifacts_dir.mkdir(exist_ok=True)
                target = artifacts_dir / f"{fetched.sha256}.{package}"
                if target.exists():
                    raise FxfetchError("artifact_exists", "Artifact path already exists")
                fetched.path.replace(target)
                result.bodies[-1]["path"] = str(target)
                result.artifacts.append(Artifact(package, target, fetched.sha256, fetched.size, fetched.url))
                emit("file_verified", chain, fetched.url, kind=package, size=fetched.size,
                     sha256=fetched.sha256)
                result.attempts.append(
                    Attempt(chain, candidate.url, "downloaded", "package_verified", "complete")
                )
                result.outcome, result.reason_code, result.coverage = (
                    "downloaded",
                    "package_verified",
                    "complete",
                )
                return
            raise FxfetchError("landing_mirrors_failed", "All verified mirrors failed within the task scope")

        def snapshot(
            html_path: Path, source: str, jar: CookieJar, chain: str,
            content_type: str | None = None, *, allow_network: bool = True
        ) -> None:
            nonlocal request_count, web_bytes
            if result.offline.get("available") or cancel.is_set():
                return
            snapshot_key = (chain, source)
            if allow_network and snapshot_key in snapshot_network_attempted:
                allow_network = False
            if allow_network:
                snapshot_network_attempted.add(snapshot_key)
            resources: dict[str, Path] = {}
            reasons: list[str] = [] if allow_network else ["offline_network_disabled_after_failure"]
            try:
                references = resource_references(html_path.read_bytes(), source, content_type)
                if len(references) > MAX_RESOURCES:
                    reasons.append("resource_limit")
                resource_bytes = 0
                for reference in references[:MAX_RESOURCES]:
                    cached = resource_cache.get((chain, reference.url))
                    if cached is not None:
                        resources[reference.url] = cached
                        resource_bytes += cached.stat().st_size
                        continue
                    if (chain, reference.url) in resource_failures:
                        reasons.append("offline_resource_previously_failed")
                        continue
                    if not allow_network:
                        continue
                    used = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
                    budget = min(
                        MAX_RESOURCE_BYTES,
                        MAX_RESOURCE_TOTAL - resource_bytes,
                        self.limits.max_web_bytes - web_bytes,
                        self.limits.max_task_bytes - metadata_reserve(self.limits) - used,
                    )
                    remaining_time = self.limits.chain_timeout - (time.monotonic() - start)
                    remaining_requests = self.limits.max_requests - request_count
                    if cancel.is_set() or budget <= 0 or remaining_time <= 0 or remaining_requests <= 0:
                        reasons.append("offline_collection_limit")
                        break
                    original_limits = self.client.limits
                    self.client.limits = replace(
                        self.limits,
                        max_package_bytes=budget,
                        max_body_bytes=budget,
                        chain_timeout=remaining_time,
                        max_requests=remaining_requests,
                    )
                    destination = output_dir / "web" / f"{request_count:04d}.resource"
                    try:
                        fetched = fetch_with_events(
                            chain, reference.url,
                            destination,
                            user_agent=ANDROID_UA if chain == "android" else IPHONE_UA,
                            cookie_jar=jar,
                            cancel=cancel,
                            referer=source,
                        )
                        first_request_id = request_count + 1
                        request_count += max(1, len(fetched.hops))
                        resource_bytes += fetched.size
                        web_bytes += fetched.size
                        result.hops.extend(hop_records(fetched.hops, chain, first_request_id))
                        result.bodies.append(
                            {
                                "path": str(fetched.path),
                                "size": fetched.size,
                                "sha256": fetched.sha256,
                                "hash_scope": "wire",
                                "complete": True,
                                "url": fetched.url,
                                "purpose": "offline_resource",
                                "chain": chain,
                                "request_id": request_count,
                                "mode": "http",
                                "user_agent": ANDROID_UA if chain == "android" else IPHONE_UA,
                            }
                        )
                        if not 200 <= fetched.status < 300:
                            reasons.append("offline_resource_http_status")
                            if fetched.status in (401, 403, 429):
                                break
                            continue
                        resources[reference.url] = fetched.path
                        resource_cache[(chain, reference.url)] = fetched.path
                    except FxfetchError as error:
                        record_partial(destination, error, reference.url, chain)
                        partial = destination.with_name(destination.name + ".partial")
                        if partial.is_file():
                            prefix_size = partial.stat().st_size
                            web_bytes += prefix_size
                            resource_bytes += prefix_size
                        request_count += max(1, len(getattr(error, "hops", ())))
                        reasons.append("offline_" + error.code)
                        if error.outcome == "blocked" or error.code not in {
                            "network_timeout",
                            "transfer_failed",
                            "dns_failed",
                            "dns_timeout",
                            "length_mismatch",
                        }:
                            break
                    finally:
                        self.client.limits = original_limits
                used = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
                bundle = OfflineBundle(self.limits).build(
                    html_path,
                    source,
                    resources,
                    output_dir / "offline" / "site",
                    max_bytes=max(0, self.limits.max_task_bytes - metadata_reserve(self.limits) - used),
                    html_content_type=content_type,
                )
                bundle.reasons.extend(reason for reason in reasons if reason not in bundle.reasons)
                result.offline = asdict(bundle)
                result.offline["source_url"] = source
            except (FxfetchError, OSError) as error:
                result.offline = {
                    "available": False,
                    "coverage": "partial",
                    "reasons": [error.code if isinstance(error, FxfetchError) else "offline_storage_failed"],
                }

        def scan_page(
            data: bytes, source: str, jar: CookieJar, chain: str, content_type: str | None = None
        ) -> list[Candidate]:
            nonlocal request_count, web_bytes, qr_bytes, qr_decode_seconds, qr_image_count
            images = discover_images(data, source, content_type=content_type)
            gaps = list(images.gaps)
            sources: list[dict[str, object]] = []
            candidates: list[Candidate] = []
            for image in images.images:
                record: dict[str, object] = {
                    "page_url": source,
                    "image_index": image.index,
                    "image_url": image.url,
                }
                sources.append(record)
                if image.skip_reason:
                    record["status"] = image.skip_reason
                    continue
                qr_image_count += 1
                if qr_image_count > MAX_IMAGES:
                    gaps.append("page_qr_image_limit")
                    break
                remaining_time = self.limits.chain_timeout - (time.monotonic() - start)
                used = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
                budget = min(
                    self.limits.max_image_bytes,
                    MAX_IMAGE_TOTAL - qr_bytes,
                    self.limits.max_web_bytes - web_bytes,
                    self.limits.max_task_bytes - metadata_reserve(self.limits) - used,
                )
                if cancel.is_set():
                    raise FxfetchError("cancelled", "Page QR scanning cancelled")
                if (
                    budget <= 0
                    or remaining_time <= 0
                    or request_count >= self.limits.max_requests
                    or qr_decode_seconds >= MAX_DECODE_SECONDS
                ):
                    gaps.append("page_qr_scan_limit")
                    break
                path = output_dir / "web" / f"qr-{len(result.bodies):04d}-{image.index}.image"
                try:
                    if image.data is not None:
                        if len(image.data) > budget:
                            raise FxfetchError("page_qr_image_limit", "Inline image exceeds budget")
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(image.data)
                        size = len(image.data)
                        digest = hashlib.sha256(image.data).hexdigest()
                        result.bodies.append(
                            {
                                "path": str(path),
                                "size": size,
                                "sha256": digest,
                                "purpose": "page_qr_inline",
                                "url": source,
                                "chain": chain,
                                "complete": True,
                                "hash_scope": "wire",
                            }
                        )
                    else:
                        assert image.url is not None
                        original_limits = self.client.limits
                        self.client.limits = replace(
                            self.limits,
                            max_package_bytes=budget,
                            max_body_bytes=budget,
                            chain_timeout=remaining_time,
                            max_requests=self.limits.max_requests - request_count,
                        )
                        try:
                            fetched = fetch_with_events(
                                chain, image.url,
                                path,
                                user_agent=ANDROID_UA if chain == "android" else IPHONE_UA,
                                cookie_jar=jar,
                                cancel=cancel,
                                referer=source,
                            )
                        except FxfetchError as error:
                            record_partial(path, error, image.url)
                            partial = path.with_name(path.name + ".partial")
                            if partial.is_file():
                                qr_bytes += partial.stat().st_size
                                web_bytes += partial.stat().st_size
                            request_count += max(1, len(getattr(error, "hops", ())))
                            raise
                        finally:
                            self.client.limits = original_limits
                        first = request_count + 1
                        request_count += max(1, len(fetched.hops))
                        result.hops.extend(hop_records(fetched.hops, chain, first))
                        path, size, digest = fetched.path, fetched.size, fetched.sha256
                        record["response_url"] = fetched.url
                        result.bodies.append(
                            {
                                "path": str(path),
                                "size": size,
                                "sha256": digest,
                                "purpose": "page_qr_image",
                                "url": fetched.url,
                                "chain": chain,
                                "request_id": request_count,
                                "complete": True,
                                "hash_scope": "wire",
                            }
                        )
                        qr_bytes += size
                        web_bytes += size
                        if fetched.status in (401, 403, 429):
                            raise FxfetchError(
                                "page_qr_access_control", "Page image access control", outcome="blocked"
                            )
                        if not 200 <= fetched.status < 300:
                            raise FxfetchError("page_qr_http_status", "Page image HTTP failure")
                        resource_cache[(chain, image.url)] = path
                    if image.data is not None:
                        qr_bytes += size
                        web_bytes += size
                    if size > budget:
                        raise FxfetchError("page_qr_image_limit", "Image exceeds budget")
                    decode_start = time.monotonic()
                    decoded = decode_saved_image(
                        path,
                        replace(
                            self.limits,
                            image_timeout=min(
                                self.limits.image_timeout,
                                MAX_DECODE_SECONDS - qr_decode_seconds,
                                max(0.01, self.limits.chain_timeout - (decode_start - start)),
                            ),
                        ),
                    )
                    qr_decode_seconds += time.monotonic() - decode_start
                    record.update({"path": str(path), "sha256": digest, "decode": asdict(decoded)})
                    if decoded.status not in ("decoded", "no_code", "no_supported_url") or decoded.truncated:
                        gaps.append("page_qr_" + (decoded.reason_code or decoded.status))
                    for code in decoded.candidates:
                        if code.url is None:
                            continue
                        parsed = classify_input(code.text)
                        if parsed.request_url is not None and parsed.kind not in ("store", "unsupported"):
                            candidate = Candidate(parsed.request_url, parsed.kind, source)
                            if not any(item.url == candidate.url for item in candidates):
                                candidates.append(candidate)
                except FxfetchError as error:
                    record["status"], record["reason_code"] = error.outcome, error.code
                    gaps.append(error.code)
                    if image.url is not None:
                        resource_failures.add((chain, image.url))
                    if error.code in {
                        "target_not_public",
                        "peer_mismatch",
                        "tls_verification_failed",
                        "tls_handshake_failed",
                        "invalid_url",
                        "invalid_header",
                        "invalid_framing",
                        "response_header_limit",
                    }:
                        raise
                    if error.outcome == "blocked":
                        prior_sources = result.page_qr.get("sources", [])
                        result.page_qr = {
                            "status": "blocked",
                            "sources": (prior_sources if isinstance(prior_sources, list) else []) + sources,
                            "gaps": gaps,
                            "candidates": [asdict(c) for c in candidates],
                        }
                        raise
            previous = result.page_qr
            previous_sources = previous.get("sources", [])
            result.page_qr = {
                "status": "partial" if gaps else "decoded" if candidates else "no_supported_url",
                "sources": (previous_sources if isinstance(previous_sources, list) else []) + sources,
                "gaps": gaps,
                "candidates": [asdict(c) for c in candidates],
            }
            for candidate in candidates:
                if candidate not in result.candidates:
                    result.candidates.append(candidate)
            if len(result.candidates) > self.limits.max_candidates:
                raise FxfetchError("candidate_limit", "Task candidate budget exhausted")
            if len(candidates) > 1:
                result.selection_candidates = list(candidates)
                raise FxfetchError(
                    "candidate_selection_required", "Multiple page QR targets require selection"
                )
            if gaps:
                raise FxfetchError("page_qr_incomplete", "Page image QR coverage incomplete")
            return candidates

        try:
            entry = classify_input(url)
            if entry.kind in ("store", "unsupported") or entry.request_url is None:
                raise FxfetchError("unsupported_input", "Input is outside supported collection scope")
            output_dir.mkdir(parents=True, exist_ok=True)
            first_chain = "iphone" if entry.kind in ("direct_ipa", "itms_manifest") else "android"
            for chain in [first_chain] if first_chain == "iphone" else ["android", "iphone"]:
                active_chain = chain
                jar = CookieJar()
                current = entry.request_url
                current_kind = entry.kind
                referer: str | None = None
                visited: set[str] = set()
                discovery_visited[chain] = visited
                while True:
                    active_url = current
                    if cancel.is_set():
                        raise FxfetchError("cancelled", "Collection cancelled")
                    if current in visited:
                        raise FxfetchError("discovery_cycle", "Static discovery loop detected")
                    visited.add(current)
                    remaining_requests = self.limits.max_requests - request_count
                    remaining_time = self.limits.chain_timeout - (time.monotonic() - start)
                    used_disk = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
                    remaining_disk = self.limits.max_task_bytes - metadata_reserve(self.limits) - used_disk
                    if remaining_requests <= 0 or remaining_time <= 0 or remaining_disk <= 0:
                        raise FxfetchError("workflow_limit", "Collection task budget exhausted")
                    package_hint = current_kind in ("direct_apk", "direct_ipa")
                    metadata_budget = min(self.limits.max_body_bytes, self.limits.max_web_bytes - web_bytes)
                    budget = min(self.limits.max_package_bytes, remaining_disk)
                    if budget <= 0 or metadata_budget <= 0:
                        raise FxfetchError("web_budget", "Metadata byte budget exhausted")
                    original_limits = self.client.limits
                    self.client.limits = replace(
                        self.limits,
                        max_package_bytes=budget,
                        max_body_bytes=metadata_budget,
                        max_requests=remaining_requests,
                        chain_timeout=remaining_time,
                    )
                    try:
                        fetched = fetch_with_events(
                            chain, current,
                            output_dir / "web" / f"{request_count:04d}.body",
                            user_agent=ANDROID_UA if chain == "android" else IPHONE_UA,
                            cookie_jar=jar,
                            cancel=cancel,
                            referer=referer,
                        )
                    except FxfetchError as error:
                        failed_path = output_dir / "web" / f"{request_count:04d}.body"
                        record_partial(failed_path, error, current)
                        partial = failed_path.with_name(failed_path.name + ".partial")
                        if partial.is_file():
                            web_bytes += partial.stat().st_size
                        request_count += max(1, len(getattr(error, "hops", ())))
                        raise
                    finally:
                        self.client.limits = original_limits
                    for hop in fetched.hops:
                        if hop.url != current and hop.url in visited:
                            raise FxfetchError("discovery_cycle", "Redirect revisits a collected page")
                        visited.add(hop.url)
                    visited.add(fetched.url)
                    first_request_id = request_count + 1
                    request_count += max(1, len(fetched.hops))
                    result.hops.extend(hop_records(fetched.hops, chain, first_request_id))
                    body_record: dict[str, object] = {
                        "path": str(fetched.path),
                        "size": fetched.size,
                        "sha256": fetched.sha256,
                        "hash_scope": "wire",
                        "complete": True,
                        "url": fetched.url,
                        "chain": chain,
                        "request_id": request_count,
                        "mode": "http",
                        "user_agent": ANDROID_UA if chain == "android" else IPHONE_UA,
                    }
                    result.bodies.append(body_record)
                    if fetched.status in (401, 403, 429):
                        raise FxfetchError(
                            "http_access_control", "HTTP access control response", outcome="blocked"
                        )
                    if not 200 <= fetched.status < 300:
                        raise FxfetchError("http_status", "Non-success HTTP response")
                    package = verify_file(fetched, chain)
                    if package:
                        wanted = "apk" if chain == "android" else "ipa"
                        if package != wanted:
                            raise FxfetchError(
                                "wrong_package_platform", "Retrieved package does not match active chain"
                            )
                        artifacts_dir = output_dir / "artifacts"
                        artifacts_dir.mkdir(exist_ok=True)
                        target = artifacts_dir / f"{fetched.sha256}.{package}"
                        if target.exists():
                            raise FxfetchError("artifact_exists", "Artifact path already exists")
                        fetched.path.replace(target)
                        body_record["path"] = str(target)
                        result.artifacts.append(
                            Artifact(package, target, fetched.sha256, fetched.size, fetched.url)
                        )
                        emit("file_verified", chain, fetched.url, kind=package, size=fetched.size,
                             sha256=fetched.sha256)
                        result.attempts.append(
                            Attempt(chain, current, "downloaded", "package_verified", "complete")
                        )
                        result.outcome, result.reason_code, result.coverage = (
                            "downloaded",
                            "package_verified",
                            "complete",
                        )
                        return result
                    if package_hint:
                        raise FxfetchError(
                            "candidate_not_package",
                            "Explicit package candidate did not return a valid package",
                        )
                    web_bytes += fetched.size
                    if fetched.size > self.limits.max_body_bytes:
                        raise FxfetchError("body_limit", "Static metadata exceeds byte limit")
                    data = fetched.path.read_bytes()
                    content_type = fetched.headers.get("content-type", "").lower()
                    if current_kind == "itms_manifest" or "plist" in content_type:
                        discovery = discover_manifest_file(
                            fetched.path,
                            fetched.url,
                            self.limits.max_candidates,
                            cancel,
                            min(5.0, max(0.01, self.limits.chain_timeout - (time.monotonic() - start))),
                        )
                    elif "html" in content_type or data.lstrip().lower().startswith(
                        (b"<!doctype html", b"<html")
                    ):
                        emit("page_received", chain, fetched.url, status=fetched.status,
                             size=fetched.size, content_type=content_type)
                        discovery = discover_html(
                            data, fetched.url, self.limits.max_candidates, content_type=content_type
                        )
                    else:
                        raise FxfetchError(
                            "content_unclassified",
                            "Response is neither a package nor supported static metadata",
                        )
                    announce_candidates(discovery.candidates, chain)
                    for candidate in discovery.candidates:
                        if candidate not in result.candidates:
                            result.candidates.append(candidate)
                    if len(result.candidates) > self.limits.max_candidates:
                        raise FxfetchError("candidate_limit", "Task candidate budget exhausted")
                    if "challenge_detected" in discovery.gaps:
                        raise FxfetchError(
                            "device_verification_required"
                            if "device_verification_detected" in discovery.gaps
                            else "challenge_detected",
                            "Static access-control indicator observed", outcome="blocked"
                        )
                    if current_kind != "itms_manifest" and (
                        "html" in content_type
                        or data.lstrip().lower().startswith((b"<!doctype html", b"<html"))
                    ):
                        last_html = (fetched.path, fetched.url, jar, chain, content_type)
                    wanted_kind = "direct_apk" if chain == "android" else "direct_ipa"
                    choices = [
                        candidate for candidate in discovery.candidates if candidate.kind == wanted_kind
                    ]
                    if not choices:
                        choices = [
                            candidate
                            for candidate in discovery.candidates
                            if candidate.kind == "http"
                            or (chain == "iphone" and candidate.kind == "itms_manifest")
                        ]
                    if not choices and chain == "android" and "browser_required" in discovery.gaps:

                        def fetch_landing_resource(
                            resource_url: str,
                            max_bytes: int,
                            *,
                            source: str = fetched.url,
                            task_jar: CookieJar = jar,
                            task_chain: str = chain,
                        ) -> bytes:
                            resource = landing_fetch(
                                resource_url, source, task_jar, task_chain, metadata_cap=max_bytes
                            )
                            return resource.path.read_bytes()

                        def fetch_flutter_resource(
                            resource_url: str,
                            max_bytes: int,
                            *,
                            source: str = fetched.url,
                            task_jar: CookieJar = jar,
                            task_chain: str = chain,
                        ) -> Path:
                            # Large compiled sources stay on disk throughout scanning.
                            resource = landing_fetch(
                                resource_url, source, task_jar, task_chain, metadata_cap=max_bytes
                            )
                            return resource.path

                        flutter = discover_flutter(
                            data, fetched.url, chain, fetch_flutter_resource,
                            content_type=content_type, cancel=cancel,
                            deadline=start + self.limits.chain_timeout,
                        )
                        if flutter.supported:
                            result.landing = {
                                "supported": True, "mirror_group": False,
                                "evidence": flutter.evidence, "gaps": flutter.gaps,
                            }
                            announce_candidates(flutter.candidates, chain)
                            for candidate in flutter.candidates:
                                if candidate not in result.candidates:
                                    result.candidates.append(candidate)
                            if len(result.candidates) > self.limits.max_candidates:
                                raise FxfetchError("candidate_limit", "Task candidate budget exhausted")
                            if flutter.candidates:
                                # Compiled string constants do not prove a reachable download action.
                                # Even one literal needs an explicit selection; never run arbitrary JS.
                                result.selection_candidates = list(flutter.candidates)
                                raise FxfetchError(
                                    "candidate_selection_required", "Select an unverified script candidate"
                                )
                            raise FxfetchError(
                                flutter.gaps[0] if flutter.gaps else "flutter_runtime_required",
                                "Flutter application coverage remains incomplete",
                            )
                        landing = discover_landing(data, fetched.url, chain, fetch_landing_resource)
                        result.landing = {
                            "supported": landing.supported,
                            "mirror_group": landing.mirror_group,
                            "evidence": landing.evidence,
                            "gaps": landing.gaps,
                        }
                        announce_candidates(landing.candidates, chain)
                        for candidate in landing.candidates:
                            if candidate not in result.candidates:
                                result.candidates.append(candidate)
                        if len(result.candidates) > self.limits.max_candidates:
                            raise FxfetchError("candidate_limit", "Task candidate budget exhausted")
                        if landing.supported:
                            choices = landing.candidates
                            result.attempts.append(
                                Attempt(chain, current, None, "landing_candidate_discovered", "partial")
                            )
                            if landing.mirror_group:
                                verify_mirrors(choices, fetched.url, jar, chain)
                                return result
                        elif landing.gaps:
                            discovery.gaps.extend(gap for gap in landing.gaps if gap not in discovery.gaps)
                    if not choices and (
                        "html" in content_type
                        or data.lstrip().lower().startswith((b"<!doctype html", b"<html"))
                    ):
                        choices = scan_page(data, fetched.url, jar, chain, content_type)
                        if (
                            len(choices) == 1
                            and choices[0].kind in ("direct_ipa", "itms_manifest")
                            and chain == "android"
                        ):
                            chain = active_chain = "iphone"
                            jar = CookieJar()
                    announce_candidates(choices, chain)
                    if len(choices) > 1:
                        result.selection_candidates = list(choices)
                        raise FxfetchError(
                            "candidate_selection_required", "Multiple candidates require explicit selection"
                        )
                    if choices:
                        chosen = choices[0]
                        result.attempts.append(
                            Attempt(chain, current, None, "candidate_discovered", "partial")
                        )
                        transport_event({"event": "redirect", "url": fetched.url,
                                         "from_url": fetched.url, "to_url": chosen.url,
                                         "mechanism": "static", "action": chosen.action}, chain)
                        referer, current, current_kind = fetched.url, chosen.url, chosen.kind
                        continue
                    if (
                        (discovery.gaps or chain == "iphone")
                        and current_kind != "itms_manifest"
                        and (
                            "html" in content_type
                            or data.lstrip().lower().startswith((b"<!doctype html", b"<html"))
                        )
                    ):
                        snapshot(fetched.path, fetched.url, jar, chain, content_type)
                        if cancel.is_set():
                            raise FxfetchError("cancelled", "Collection cancelled during optional snapshot")
                    if discovery.gaps:
                        raise FxfetchError(
                            "browser_required",
                            "Static coverage incomplete; protected Chrome collection is unavailable",
                        )
                    result.attempts.append(
                        Attempt(chain, current, "not_found", "static_scope_complete", "complete")
                    )
                    break
                if chain == "iphone":
                    break
            result.outcome, result.reason_code, result.coverage = (
                "not_found",
                "static_scope_complete",
                "complete",
            )
        except FxfetchError as exc:
            result.outcome, result.reason_code, result.coverage = exc.outcome, exc.code, "partial"
            if exc.outcome == "blocked":
                emit("challenge_detected", active_chain, active_url, reason_code=exc.code)
            elif exc.code == "browser_required" or exc.code.startswith("flutter_"):
                emit("browser_required", active_chain, active_url, reason_code=exc.code)
            attempt = Attempt(active_chain, active_url, exc.outcome, exc.code, "partial")
            if not result.attempts or result.attempts[-1] != attempt:
                result.attempts.append(attempt)
        except OSError:
            result.outcome, result.reason_code, result.coverage = "failed", "storage_failed", "partial"
            result.attempts.append(Attempt(active_chain, active_url, "failed", "storage_failed", "partial"))
        if result.outcome != "downloaded" and not cancel.is_set() and last_html is not None:
            ordinary_failure = result.outcome != "blocked" and result.reason_code in {
                "network_timeout",
                "transfer_failed",
                "dns_failed",
                "dns_timeout",
                "http_status",
                "candidate_not_package",
                "landing_mirrors_failed",
                "content_unclassified",
                "discovery_cycle",
                "browser_required",
                "page_qr_incomplete",
                "page_qr_http_status",
                "static_scope_complete",
            }
            snapshot(*last_html, allow_network=ordinary_failure)
        return result
