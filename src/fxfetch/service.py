"""Serial background workers shared by CLI and HTTP adapters."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import shutil
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urldefrag, urlsplit

from filelock import FileLock

from . import __version__
from .analysis_service import AnalysisService
from .config import Settings
from .core.classify import classify_input, normalize_entry_url
from .core.errors import FxfetchError
from .core.network import AcquisitionPolicy
from .core.process_limits import run_limited
from .core.proxy import LocalConnectProxy
from .core.task_evidence import (
    finalize_package,
    package_directory,
    package_file,
    package_metadata,
    write_package_metadata,
)
from .core.task_evidence_recorder import TaskEvidenceRecorder
from .core.tls_policy import web_tls_policy
from .core.web_apk import WebApkBuilder, derive_names
from .core.workflow import Workflow
from .rejected_files import open_rejected_file, rejected_files
from .security import contained_path
from .store import TERMINAL, Store, json_text

log = logging.getLogger(__name__)


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(".tmp")
    pending.write_text(json_text(value), encoding="utf-8")
    pending.replace(path)


class JobService:
    def __init__(
        self, settings: Settings, *, workflow: Workflow | None = None, builder: WebApkBuilder | None = None
    ):
        self.settings = settings
        self._isolated_collect = workflow is None
        self._isolated_build = builder is None or type(builder) is WebApkBuilder
        self.store = Store(settings.root)
        proxy = LocalConnectProxy(settings.proxy_host, settings.proxy_port) if settings.proxy_host else None
        self.workflow = workflow or AcquisitionPolicy(settings.limits, proxy, browser_root=settings.root)
        self.builder = builder or WebApkBuilder()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._mutex = threading.RLock()
        self._cancels: dict[str, threading.Event] = {}
        self._data_package_active: set[str] = set()
        self._threads: list[threading.Thread] = []
        self._instance_lock = FileLock(self.store.root / "service.lock", thread_local=False)
        self._next_cleanup = 0.0
        self._chrome_probe_at: float | None = None
        self._chrome_probe_lock = threading.Lock()
        self._chrome_probe_running = False
        self._chrome_probe_thread: threading.Thread | None = None
        self._chrome_capability: dict = {"enabled": False, "reason_code": "browser_guard_unavailable"}
        self.analysis = AnalysisService(self)

    def start(self) -> None:
        self._instance_lock.acquire(timeout=0)
        self.store.restart_interrupt()
        self.analysis.start()
        for kind in ("collect", "build", "maintenance"):
            worker = threading.Thread(target=self._loop, args=(kind,), daemon=True, name=f"fxfetch-{kind}")
            self._threads.append(worker)
            worker.start()

    def close(self) -> None:
        with self._mutex:
            self._stop.set()
            self.analysis.stop_locked()
            self._wake.set()
            for event in self._cancels.values():
                event.set()
        for thread in self._threads:
            thread.join(timeout=25)
        if not any(thread.is_alive() for thread in self._threads):
            self._instance_lock.release()

    def _probe_chrome(self) -> None:
        # AndroidWorker's subprocess has a fixed timeout. This one daemon is
        # observational only: collection still obtains a fresh live lease proof.
        value = {"enabled": False, "reason_code": "browser_worker_unavailable"}
        try:
            from .core.android_worker import AndroidWorker, load_worker_config

            config = load_worker_config(self.settings.root)
            value = AndroidWorker(config).probe() if config else {
                "enabled": False, "reason_code": "browser_guard_unavailable"
            }
        except FxfetchError as exc:
            value = {"enabled": False, "reason_code": exc.code}
        except Exception as exc:
            # A background boundary must publish failure and release its slot,
            # without exposing configuration paths or exception text to clients.
            log.error("browser_capability_probe_failed exception_type=%s", type(exc).__name__)
        finally:
            with self._chrome_probe_lock:
                self._chrome_capability = value
                self._chrome_probe_at = time.monotonic()
                self._chrome_probe_running = False

    def _browser_capability(self) -> dict:
        with self._chrome_probe_lock:
            stale = self._chrome_probe_at is None or time.monotonic() - self._chrome_probe_at > 30
            if stale and not self._chrome_probe_running and not self._stop.is_set():
                self._chrome_probe_running = True
                self._chrome_probe_thread = threading.Thread(
                    target=self._probe_chrome, daemon=True, name="fxfetch-browser-readiness"
                )
                try:
                    self._chrome_probe_thread.start()
                except RuntimeError:
                    self._chrome_probe_running = False
                    self._chrome_probe_at = time.monotonic()
                    self._chrome_capability = {
                        "enabled": False, "reason_code": "browser_worker_unavailable"
                    }
            return {
                **self._chrome_capability,
                "checking": self._chrome_probe_running,
                "cached": self._chrome_probe_at is not None,
            }

    def capabilities(self) -> dict:
        build = self.builder.probe()
        return {
            "http": {"enabled": True, "coverage": "static_http"},
            "chrome": self._browser_capability(),
            "web_apk": {
                "enabled": build.enabled,
                "reasons": list(build.reasons),
                "scratch_limit_method": getattr(build, "scratch_limit_method", "unavailable"),
            },
            "web_analysis": self.analysis.capability(),
            "version": __version__,
            "dns": ["223.5.5.5", "119.29.29.29"],
            "network_policy": {
                "default_mode": "direct",
                "proxy_fallback_configured": self.settings.proxy_host is not None,
                "max_proxy_attempts": 1,
                "fallback_scope": "initial_transport_failure_before_response",
                "session_continuity": "independent_request_session",
            },
            "allowed_networks": list(self.settings.allowed_networks),
            "task_limits": {
                "collection_seconds": self.settings.limits.chain_timeout,
                "build_seconds": self.settings.limits.build_timeout,
                "queue_budget": "separate_same_duration",
                "execution_limit_method": "isolated_process_tree"
                if self._isolated_collect and self._isolated_build
                else "mixed_or_injected",
                "collection_limit_method": "isolated_process_tree"
                if self._isolated_collect
                else "injected_test_callable",
                "build_limit_method": "isolated_process_tree"
                if self._isolated_build
                else "injected_test_callable",
            },
        }

    def create_job(self, owner: str, idem: str, value: dict) -> dict:
        try:
            tls_policy = web_tls_policy(value)
        except ValueError as error:
            raise FxfetchError('invalid_input', str(error)) from error
        value = {key: item for key, item in value.items() if key != 'ignore_tls_errors'}
        value['tls_policy'] = tls_policy
        existing = self.store.replay_job(owner, idem, value)
        if existing:
            return self.get_job(owner, existing["id"])
        source: dict = {"kind": "manual_url", "entry_url": value.get("url")}
        image = None
        if value.get("image_id"):
            image = self.store.image(owner, value["image_id"])
            if image["result"].get("truncated"):
                raise FxfetchError("qr_truncated", "Crop the image and decode again")
            selected = next(
                (item for item in image["result"]["candidates"] if item["id"] == value.get("candidate_id")),
                None,
            )
            if selected is None or selected.get("url") is None:
                raise FxfetchError("invalid_selection", "Select a valid QR URL")
            original = selected["text"] if selected["kind"] == "itms_manifest" else selected["url"]
            source = {
                "kind": "edited_qr" if value.get("url") else "qr_image",
                "entry_url": value.get("url") or original,
                "image_id": value["image_id"],
                "candidate_id": selected["id"],
                "qr_original": selected["text"],
                "image_sha256": image["result"]["sha256"],
            }
        if not isinstance(source["entry_url"], str):
            raise FxfetchError("invalid_input", "URL is required")
        normalized_entry = normalize_entry_url(source["entry_url"])
        if normalized_entry != source["entry_url"]:
            source["original_input"] = source["entry_url"]
            source["entry_url"] = normalized_entry
        classified = classify_input(source["entry_url"])
        source['tls_policy'] = tls_policy
        if classified.kind in ("unsupported", "store") or classified.request_url is None:
            raise FxfetchError("unsupported_input", "Unsupported URL type")
        # Preserve the typed source separately when a scheme was completed;
        # the entry keeps query/fragment exactly and only transport encodes it.
        with self._mutex:
            job, created = self.store.create_job(
                owner, idem, source, self.settings.limits.max_queued_jobs, value
            )
            if created:
                try:
                    try:
                        write_package_metadata(
                            package_directory(self.store.root / "jobs" / job["id"]),
                            {"state": "pending"},
                        )
                    except OSError:
                        log.error("data_package_pending_write_failed id=%s", job["id"])
                    directory = self.store.root / "jobs" / job["id"] / "source"
                    directory.mkdir(parents=True, exist_ok=True)
                    if image:
                        shutil.copyfile(
                            contained_path(self.store.root, image["path"]), directory / "image.original"
                        )
                        atomic_json(directory / "qr.json", image["result"])
                    atomic_json(directory / "input.json", source)
                    if image:
                        self.store.mark_image_used(owner, value["image_id"])
                except Exception:
                    # The worker takes this same mutex: an unrecorded input is never runnable.
                    self.store.fail_pending_job(job["id"])
                    raise
            self._wake.set()
        return self.get_job(owner, job["id"])

    def get_job(self, owner: str, identifier: str) -> dict:
        job = self.store.get_job(owner, identifier)
        job['tls_policy'] = job['input'].get('tls_policy') or (
            'legacy_ignore' if job['input'].get('ignore_tls_errors') is True else 'strict')
        job['rejected_files'] = [item.metadata for item in rejected_files(
            job, self.store.root / 'jobs' / identifier, self.settings.limits.max_package_bytes)]
        job.pop("owner", None)
        if job["state"] == "queued":
            job["progress"] = self._queued_progress(job, self.settings.limits.chain_timeout)
        for build in job.get("builds", []):
            if build["state"] == "queued":
                build["progress"] = self._queued_progress(build, self.settings.limits.build_timeout)
        result = job.get("result") or {}
        # Bodies, raw response headers and host paths stay in private evidence.
        job["result"] = {
            key: result[key]
            for key in (
                "outcome",
                "reason_code",
                "coverage",
                "attempts",
                "candidates",
                "selection_candidates",
                "network_mode",
                "collector_mode",
            )
            if key in result
        }
        job["result"]["network_attempts"] = [
            {
                **{
                    key: attempt[key]
                    for key in ("attempt_id", "network_mode", "session_continuity", "cookies_inherited")
                    if key in attempt
                },
                "result": {
                    key: attempt["result"][key]
                    for key in ("outcome", "reason_code", "coverage")
                    if key in attempt.get("result", {})
                },
            }
            for attempt in result.get("network_attempts", [])[:2]
        ]
        if "collector_mode" not in job["result"]:
            observed_modes = {hop.get("mode") for hop in result.get("hops", [])}
            if observed_modes == {"http"}:
                job["result"]["collector_mode"] = "http"
        offline = result.get("offline") or {}
        job["result"]["offline"] = {
            key: offline[key] for key in ("available", "bytes", "coverage", "reasons") if key in offline
        }
        scan = result.get("page_qr") or {}
        job["result"]["page_qr"] = {key: scan[key] for key in ("status", "gaps", "candidates") if key in scan}
        job["download_selection_unavailable"] = (
            result.get("reason_code") == "candidate_selection_required"
            and "selection_candidates" not in result
        )
        job["download_candidates"] = self.download_candidates(job)
        children = self.store.continuation_children(owner, identifier)
        child_id = next(
            (item["child_id"] for item in children if item["state"] in {"queued", "running"}), None
        )
        job["continuation_child_job_id"] = child_id
        job["continuation_active_child_job_id"] = child_id
        child_map = {item["candidate_id"]: item["child_id"] for item in children}
        for candidate in job["download_candidates"]:
            candidate["child_job_id"] = child_map.get(candidate["id"])
        job["web_candidates"] = self.web_candidates(job)
        with self._mutex:
            job["data_package"] = package_metadata(
                self.store.root / "jobs" / identifier,
                job["state"],
                active=identifier in self._data_package_active,
            )
        job["analyses"] = self.analysis.list(owner, identifier)
        job['tls_fallback'] = job['data_package'].get('tls_fallback', {
            'state': 'pending' if job['state'] not in TERMINAL else 'unavailable',
            'count': 0, 'observed': False, 'reasons': [],
        })
        return job

    def rejected_file(self, owner: str, identifier: str, file_id: str) -> tuple[BinaryIO, dict]:
        job = self.store.get_job(owner, identifier)
        return open_rejected_file(job, self.store.root / 'jobs' / identifier, file_id,
                                  self.settings.limits.max_package_bytes)

    def data_package_file(self, owner: str, identifier: str) -> tuple[Path, str]:
        job = self.store.get_job(owner, identifier)
        folder = self.store.root / "jobs" / identifier
        with self._mutex:
            metadata = package_metadata(
                folder, job["state"], active=identifier in self._data_package_active
            )
        try:
            path = package_file(folder, metadata, self.settings.limits.max_task_bytes)
        except Exception as error:
            raise FxfetchError("not_found", "Data package is unavailable") from error
        return path, metadata["filename"]

    def analysis_source_descriptor(self, owner: str, identifier: str) -> dict:
        job = self.store.get_job(owner, identifier)
        if job["state"] not in TERMINAL:
            raise FxfetchError("not_found", "Data package is unavailable")
        folder = self.store.root / "jobs" / identifier
        with self._mutex:
            metadata = package_metadata(
                folder, job["state"], active=identifier in self._data_package_active
            )
        try:
            if metadata.get("state") != "ready":
                raise ValueError("data package is not ready")
            relative = (
                Path("jobs") / identifier / "data-package" / metadata["filename"]
            ).as_posix()
            path = contained_path(self.store.root, relative)
            size = path.stat().st_size
            if size != metadata["size"] or size > self.settings.limits.max_task_bytes:
                raise ValueError("data package size mismatch")
        except (FxfetchError, OSError, TypeError, ValueError) as error:
            raise FxfetchError("not_found", "Data package is unavailable") from error
        return {"path": relative, "size": size, "sha256": metadata["sha256"]}

    @staticmethod
    def download_candidates(job: dict) -> list[dict]:
        """Expose only server-observed, offline-validated choices; never resolve here."""
        if job["state"] != "completed" or job.get("outcome") == "downloaded":
            return []
        result = job.get("result") or {}
        if result.get("reason_code") != "candidate_selection_required":
            return []
        choices: list[dict] = []
        seen: set[str] = set()
        for item in result.get("selection_candidates", []):
            url = item.get("url")
            if not isinstance(url, str) or url == job["input"]["entry_url"] or url in seen:
                continue
            try:
                parsed = classify_input(url)
            except (FxfetchError, ValueError):
                continue
            if parsed.kind not in {"http", "direct_apk", "direct_ipa", "itms_manifest"}:
                continue
            if item.get("kind") not in {"http", "direct_apk", "direct_ipa", "itms_manifest"}:
                continue
            seen.add(url)
            choices.append(
                {
                    "id": hashlib.sha256((job["id"] + "\0" + url).encode()).hexdigest()[:24],
                    "url": url,
                    "kind": item["kind"],
                    "source_url": item.get("source_url", ""),
                    "label": item.get("label", ""),
                }
            )
        return choices

    def continue_job(self, owner: str, parent_id: str, idem: str, candidate_id: str,
                     ignore_tls_errors: bool | None = None, *, tls_policy: str | None = None) -> dict:
        choices = {**({'ignore_tls_errors': ignore_tls_errors} if ignore_tls_errors is not None else {}),
                   **({'tls_policy': tls_policy} if tls_policy is not None else {})}
        try:
            tls_policy = web_tls_policy(choices)
        except ValueError as error:
            raise FxfetchError('invalid_input', str(error)) from error
        with self._mutex:
            parent = self.get_job(owner, parent_id)
            request = {"parent_job_id": parent_id, "candidate_id": candidate_id, 'tls_policy': tls_policy}
            existing = self.store.replay_job(owner, idem, request)
            if existing:
                return self.get_job(owner, existing["id"])
            candidate = next(
                (item for item in parent["download_candidates"] if item["id"] == candidate_id), None
            )
            if candidate is None:
                raise FxfetchError("invalid_selection", "Select a discovered download candidate")
            ancestors: list[str] = []
            current = parent
            for _ in range(5):
                ancestors.append(current["input"]["entry_url"])
                previous = current["input"].get("parent_job_id")
                if not previous:
                    break
                current = self.store.get_job(owner, previous)
            depth = len(ancestors)
            if depth > 4:
                raise FxfetchError("continuation_limit", "Selection depth limit reached")
            selected_url = urldefrag(classify_input(candidate["url"]).request_url or "")[0]
            if any(urldefrag(classify_input(url).request_url or "")[0] == selected_url for url in ancestors):
                raise FxfetchError("continuation_cycle", "Candidate returns to an earlier entry")
            source = {
                "kind": "download_candidate",
                "entry_url": candidate["url"],
                "parent_job_id": parent_id,
                "parent_entry_url": parent["input"]["entry_url"],
                "selected_candidate_id": candidate_id,
                "source_url": candidate["source_url"],
                "selected_candidate_kind": candidate["kind"],
                "session_continuity": "independent_request_session",
                "cookies_inherited": False,
                "continuation_depth": depth,
                'tls_policy': tls_policy,
            }
            job, created = self.store.create_continuation(
                owner, parent_id, candidate_id, idem, source, self.settings.limits.max_queued_jobs
            )
            if created:
                try:
                    atomic_json(self.store.root / "jobs" / job["id"] / "source" / "input.json", source)
                except Exception:
                    self.store.fail_pending_job(job["id"])
                    raise
            self._wake.set()
            return self.get_job(owner, job["id"])

    @staticmethod
    def web_candidates(job: dict) -> list[dict]:
        if job["state"] not in TERMINAL or job.get("outcome") == "downloaded":
            return []
        entry = job["input"]["entry_url"]
        try:
            classified = classify_input(entry)
            if classified.kind != "http" or urlsplit(entry).path.lower().endswith(
                (".plist", ".mobileconfig")
            ):
                return []
            names = derive_names(entry)
        except (FxfetchError, ValueError):
            return []
        return [
            {
                "id": hashlib.sha256(entry.encode()).hexdigest()[:24],
                "url": entry,
                "filename": names.filename,
                "package_base": names.package_base,
            }
        ]

    def clear_jobs(self, owner: str) -> dict:
        with self._mutex:
            self.analysis.cancel_owner(owner)
            count, active = self.store.clear_jobs(owner)
            for identifier in active:
                event = self._cancels.get(identifier)
                if event is not None:
                    event.set()
            with self.store.connect() as database:
                images = list(database.execute("SELECT path FROM images WHERE owner=?", (owner,)))
                database.execute("DELETE FROM images WHERE owner=?", (owner,))
            for image in images:
                for relative in (image["path"], image["path"] + ".jpg"):
                    try:
                        contained_path(self.store.root, relative, must_exist=False).unlink(missing_ok=True)
                    except FxfetchError:
                        pass  # Refuse replaced links; never follow them during cleanup.
                    except OSError as error:
                        log.warning("image_cleanup_failed exception_type=%s", type(error).__name__)
            self._wake.set()
        return {"cleared": count}

    def cancel_job(self, owner: str, identifier: str) -> dict:
        with self._mutex:
            was_queued = self.store.get_job(owner, identifier)["state"] == "queued"
            self.store.cancel_queued_job(owner, identifier)
            if was_queued:
                # No acquisition ran and no archive is promised for this path.
                # Do not leave pending metadata looking like an interrupted seal.
                try:
                    write_package_metadata(
                        package_directory(self.store.root / "jobs" / identifier), {"state": "unavailable"},
                    )
                except (OSError, ValueError) as error:
                    log.error("data_package_cancel_state_failed id=%s exception_type=%s",
                              identifier, type(error).__name__)
            if identifier in self._cancels:
                self._cancels[identifier].set()
        return self.get_job(owner, identifier)

    def create_build(self, owner: str, job_id: str, idem: str, candidate_id: str) -> dict:
        with self._mutex:
            job = self.get_job(owner, job_id)
            candidate = next((value for value in job["web_candidates"] if value["id"] == candidate_id), None)
            if candidate is None:
                raise FxfetchError("invalid_build_source", "No eligible webpage in this completed job")
            existing = self.store.replay_build(owner, job_id, idem, candidate["url"])
            if existing:
                return existing
            capability = self.builder.probe()
            if not capability.enabled:
                raise FxfetchError("build_unavailable", ",".join(capability.reasons))
            result = self.store.create_build(
                owner,
                job_id,
                idem,
                candidate["url"],
                derive_names(candidate["url"]),
                self.settings.limits.max_queued_builds,
            )
            if result["state"] == "queued":
                result["progress"] = self._queued_progress(result, self.settings.limits.build_timeout)
            self._wake.set()
            return result

    def get_build(self, owner: str, job_id: str, identifier: str) -> dict:
        result = self.store.get_build(owner, job_id, identifier)
        if result["state"] == "queued":
            result["progress"] = self._queued_progress(result, self.settings.limits.build_timeout)
        return result

    def cancel_build(self, owner: str, job_id: str, identifier: str) -> dict:
        with self._mutex:
            self.store.cancel_queued_build(owner, job_id, identifier)
            if identifier in self._cancels:
                self._cancels[identifier].set()
        return self.store.get_build(owner, job_id, identifier)

    def _loop(self, kind: str) -> None:
        if kind == "maintenance":
            while not self._stop.wait(1):
                try:
                    self._expire_queued()
                    self.analysis.expire_queued()
                except (sqlite3.Error, OSError) as error:
                    log.error("queue_expiry_failed exception_type=%s", type(error).__name__)
            return
        while not self._stop.is_set():
            with self._mutex:
                if time.monotonic() >= self._next_cleanup:
                    try:
                        self.cleanup_images()
                    except OSError as exc:
                        log.warning("image_cleanup_failed exception_type=%s", type(exc).__name__)
                    self._next_cleanup = time.monotonic() + 60
                item = self.store.claim_job() if kind == "collect" else self.store.claim_build()
                if item:
                    cancel = threading.Event()
                    self._cancels[item["id"]] = cancel
            if item is None:
                self._wake.wait(1)
                self._wake.clear()
                continue
            try:
                if kind == "collect":
                    self._collect(item, cancel)
                else:
                    self._build(item, cancel)
            except Exception as exc:
                # Metadata only: exception text can contain target secrets and local paths.
                log.error(
                    "worker_error kind=%s id=%s exception_type=%s", kind, item["id"], type(exc).__name__
                )
                failure = {"outcome": "failed", "reason_code": "internal_error", "coverage": "incomplete"}
                if kind == "collect":
                    self.store.finish_job(item["id"], "completed", failure)
                else:
                    self.store.finish_build(item["id"], "failed", failure)
            finally:
                with self._mutex:
                    self._cancels.pop(item["id"], None)

    @staticmethod
    def _queued_progress(item: dict, timeout: float) -> dict:
        return {
            **(item.get("progress") or {}),
            "event": "queued",
            "events": [],
            "queue_deadline_at": item["created"] + timeout,
            "queue_timeout_seconds": timeout,
        }

    def _start_progress(self, identifier: str, timeout: float, *, build: bool = False) -> tuple[float, float]:
        started, monotonic = time.time(), time.monotonic()
        self.store.progress(
            identifier,
            {
                "event": "building" if build else "task_started",
                "started_at": started,
                "deadline_at": started + timeout,
                "timeout_seconds": timeout,
                "execution_limit_method": "isolated_process_tree"
                if (self._isolated_build if build else self._isolated_collect)
                else "injected_test_callable",
            },
            build=build,
        )
        return started, monotonic + timeout

    def _isolated(self, request: dict, folder: Path, deadline: float, cancel: threading.Event) -> dict:
        folder.mkdir(parents=True, exist_ok=True)
        request_path, result_path = folder / "worker-request.json", folder / "worker-result.json"
        result_path.unlink(missing_ok=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {
                "outcome": "failed",
                "state": "failed",
                "reason_code": "build_timeout" if request["operation"] == "build" else "task_timeout",
                "coverage": "partial",
            }
        # This identity is generated by the supervisor, never by HTTP input.
        # Keep it outside the killable worker so hard cancellation can release
        # precisely its remote lease after the local process tree has stopped.
        request = dict(request)
        request.pop("android_lease_id", None)
        android_worker = None
        android_lease_id = None
        if request["operation"] == "collect" and classify_input(request["url"]).kind == "http":
            from .core.android_worker import AndroidWorker, load_worker_config

            try:
                worker_config = load_worker_config(self.settings.root)
            except FxfetchError as error:
                return {"outcome": "failed", "reason_code": error.code, "coverage": "not_started"}
            if worker_config is not None:
                android_worker = AndroidWorker(worker_config)
                android_lease_id = uuid.uuid4().hex
                request["android_lease_id"] = android_lease_id
        atomic_json(request_path, request)

        def release_android() -> None:
            if android_worker is None or android_lease_id is None:
                return
            self._chrome_probe_at = 0.0
            try:
                # AndroidWorker.call has a fixed 30-second cleanup deadline.
                # The guest accepts replay only for this exact lease ID.
                ended = android_worker.call("end", android_lease_id)
                if ended.get("state") != "ended" or ended.get("lease_id") != android_lease_id:
                    raise FxfetchError("browser_worker_protocol", "Android cleanup was not confirmed")
            except FxfetchError as error:
                # Preserve cancellation/timeout and validated result semantics.
                # Guest deadline remains the final guard if control is offline.
                log.warning("android_cleanup_failed reason_code=%s", error.code)

        result = run_limited(
            [sys.executable, "-m", "fxfetch.task_worker", str(request_path), str(result_path)],
            timeout=remaining,
            memory_bytes=self.settings.limits.build_memory_bytes,
            cancel=cancel,
            max_output_bytes=65536,
        )
        code = (
            "cancelled"
            if cancel.is_set() or result.cancelled
            else ("build_timeout" if request["operation"] == "build" else "task_timeout")
            if result.timed_out or time.monotonic() >= deadline
            else "worker_failed"
            if result.returncode != 0 or result.reason_code
            else None
        )
        if code:
            release_android()
            return {
                "outcome": "failed",
                "state": "cancelled" if code == "cancelled" else "failed",
                "reason_code": code,
                "coverage": "partial",
            }
        if not result_path.is_file() or result_path.stat().st_size > 16 * 1024 * 1024:
            release_android()
            return {
                "outcome": "failed",
                "state": "failed",
                "reason_code": "worker_result_invalid",
                "coverage": "partial",
            }
        try:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("worker_result_not_object")
        except (OSError, ValueError):
            release_android()
            return {
                "outcome": "failed", "state": "failed", "reason_code": "worker_result_invalid",
                "coverage": "partial",
            }
        return value

    def _expire_queued(self) -> None:
        with self._mutex:
            expired = self.store.expire_queued(
                self.settings.limits.chain_timeout, self.settings.limits.build_timeout
            )
            identifiers = {job["id"] for job in expired}
            self._data_package_active.update(identifiers)
        try:
            for job in expired:
                self._seal_data_package(job, job["result"])
        finally:
            with self._mutex:
                self._data_package_active.difference_update(identifiers)

    def _seal_data_package(self, job: dict, result: dict) -> None:
        folder = self.store.root / "jobs" / job["id"]
        try:
            write_package_metadata(package_directory(folder), {"state": "building"})
        except OSError:
            log.error("data_package_state_write_failed id=%s", job["id"])
        try:
            package_result = finalize_package(
                folder,
                job_id=job["id"],
                entry_url=job["input"]["entry_url"],
                terminal_result=result,
                observation_path=folder / "task-observations.jsonl",
                max_bytes=self.settings.limits.max_task_bytes,
                ignore_tls_errors=job['input'].get('ignore_tls_errors', False) is True,
                tls_policy=job['input'].get('tls_policy'),
            )
            if package_result.get("state") == "failed":
                log.error(
                    "data_package_finalize_failed id=%s reason_code=%s",
                    job["id"], package_result.get("reason_code"),
                )
        except Exception as error:
            log.error("data_package_finalize_failed id=%s exception_type=%s",
                      job["id"], type(error).__name__)

    def _expired_claim(self, item: dict, *, build: bool = False) -> bool:
        timeout = self.settings.limits.build_timeout if build else self.settings.limits.chain_timeout
        if time.time() < item["created"] + timeout:
            return False
        result = {"outcome": "failed", "reason_code": "queue_timeout", "coverage": "not_started"}
        self.store.progress(
            item["id"], {"event": "queue_timeout", "reason_code": "queue_timeout"}, build=build
        )
        if build:
            self.store.finish_build(item["id"], "failed", result)
        else:
            self.store.finish_job(item["id"], "completed", result)
            self._seal_data_package(item, result)
        return True

    def _collect(self, job: dict, cancel: threading.Event) -> None:
        with self._mutex:
            self._data_package_active.add(job["id"])
        try:
            self._collect_claimed(job, cancel)
        except Exception as error:
            log.error("worker_error kind=collect id=%s exception_type=%s", job["id"], type(error).__name__)
            failure = {"outcome": "failed", "reason_code": "internal_error", "coverage": "incomplete"}
            self.store.finish_job(job["id"], "completed", failure)
            # Keep archive ownership until the terminal failure and any already
            # recorded materials have gone through the normal bounded finalizer.
            self._seal_data_package(job, failure)
        finally:
            with self._mutex:
                self._data_package_active.discard(job["id"])

    def _collect_claimed(self, job: dict, cancel: threading.Event) -> None:
        if self._expired_claim(job):
            return
        folder = self.store.root / "jobs" / job["id"]
        try:
            write_package_metadata(package_directory(folder), {"state": "pending"})
        except OSError:
            log.error("data_package_state_write_failed id=%s", job["id"])
        recorder = None if self._isolated_collect else TaskEvidenceRecorder(folder)
        tls_policy = job['input'].get('tls_policy') or (
            'auto' if job['input'].get('ignore_tls_errors') is True else 'strict')
        if recorder is not None:
            recorder.append('task_tls_policy', {'tls_policy': tls_policy})
        started, deadline = self._start_progress(job["id"], self.settings.limits.chain_timeout)
        value: dict[str, Any]
        if self._isolated_collect:
            value = self._isolated(
                {
                    "operation": "collect",
                    "root": str(self.store.root),
                    "identifier": job["id"],
                    "url": job["input"]["entry_url"],
                    "output_dir": str(folder),
                    "observation_path": str(folder / "task-observations.jsonl"),
                    "limits": asdict(self.settings.limits),
                    "proxy_host": self.settings.proxy_host,
                    "proxy_port": self.settings.proxy_port,
                    'tls_policy': tls_policy,
                },
                folder / "worker",
                deadline,
                cancel,
            )
        else:
            def progress(event: dict) -> None:
                self.store.progress(job["id"], event)
                if recorder is not None:
                    recorder.observe_progress(event)

            try:
                workflow = self.workflow
                if isinstance(workflow, Workflow) and hasattr(workflow, 'client'):
                    # Test-injected collectors remain per-task; never mutate a
                    # shared client's TLS policy for the next queued task.
                    workflow = copy.copy(workflow)
                    client = getattr(workflow, 'client', None)
                    if client is not None:
                        workflow.client = copy.copy(client)  # type: ignore[union-attr]
                        workflow.client.tls_policy = tls_policy  # type: ignore[union-attr]
                        workflow.client.ignore_tls_errors = tls_policy == 'auto'  # type: ignore[union-attr]
                value = asdict(
                    workflow.run(
                    job["input"]["entry_url"],
                    folder,
                    cancel,
                    progress,
                    )
                )
            finally:
                if recorder is not None:
                    recorder.close()
        if cancel.is_set() or time.monotonic() >= deadline:
            value = {
                "outcome": "failed",
                "reason_code": "cancelled" if cancel.is_set() else "task_timeout",
                "coverage": "partial",
            }
        state = "cancelled" if cancel.is_set() else "completed"
        artifacts: list[dict] = []
        for artifact in value.get("artifacts", []):
            if cancel.is_set() or time.monotonic() >= deadline:
                value = {
                    "outcome": "failed",
                    "reason_code": "cancelled" if cancel.is_set() else "task_timeout",
                    "coverage": "partial",
                }
                break
            path = Path(artifact["path"]).absolute()
            relative = str(path.relative_to(self.store.root))
            contained_path(self.store.root, relative)
            artifacts.append(
                {
                    "job_id": job["id"],
                    "owner": job["owner"],
                    "path": relative,
                    "filename": f"{artifact['sha256']}.{artifact['kind']}",
                    "kind": artifact["kind"],
                    "sha256": artifact["sha256"],
                    "size": artifact["size"],
                    "origin": "downloaded_original",
                }
            )
        evidence = {
            "schema_version": 1,
            "run": {
                "version": __version__,
                "authorized_by": "candidate_selection"
                if job["input"].get("kind") == "download_candidate"
                else "download_action",
                "started": started,
                "limits": asdict(self.settings.limits),
                'tls_policy': tls_policy,
            },
            "input": job["input"],
            "worker_summary": value,
            "terminal_status": "pending_database_commit",
            "authoritative_record": {"store": "service.sqlite3", "job_id": job["id"]},
        }
        # Prewrite is explicitly provisional; it never claims the worker's result was published.
        atomic_json(folder / "evidence.json", evidence)
        terminal = self.store.finish_with_artifacts(job["id"], state, value, artifacts, deadline, cancel)
        evidence.update(summary=terminal["result"], job_state=terminal["state"], terminal_status="committed")
        evidence["run"]["finished"] = time.time()
        try:
            atomic_json(folder / "evidence.json", evidence)
        except OSError as error:
            # The committed SQLite result stays authoritative if the final evidence write fails.
            log.error("final_evidence_write_failed id=%s exception_type=%s", job["id"], type(error).__name__)
        self._seal_data_package(job, terminal["result"])

    def _build(self, build: dict, cancel: threading.Event) -> None:
        if self._expired_claim(build, build=True):
            return
        started, deadline = self._start_progress(build["id"], self.settings.limits.build_timeout, build=True)
        folder = self.store.root / "jobs" / build["job_id"]
        used = sum(path.stat().st_size for path in folder.rglob("*") if path.is_file())
        if self.settings.limits.max_task_bytes - used < self.settings.limits.max_package_bytes:
            self.store.finish_build(build["id"], "failed", {"reason_code": "task_disk_budget"})
            return
        original = self.store.get_job(build["owner"], build["job_id"], include_archived=True)
        offline = (original.get("result") or {}).get("offline") or {}
        options = {}
        if offline.get("available") and offline.get("entry"):
            entry = Path(offline["entry"]).absolute()
            relative = str(entry.relative_to(self.store.root))
            options["offline_dir"] = contained_path(self.store.root, relative).parent
        value: dict[str, Any]
        scratch = None
        if self._isolated_build:
            base = self.builder.settings.scratch_root or self.store.root / ".build-private" / "scratch"
            base.mkdir(parents=True, exist_ok=True)
            scratch = base / ("task-" + build["id"])
            scratch.mkdir(exist_ok=False)
            settings = replace(self.builder.settings, scratch_root=scratch)
            try:
                value = self._isolated(
                    {
                        "operation": "build",
                        "root": str(self.store.root),
                        "identifier": build["id"],
                        "url": build["url"],
                        "output_dir": str(folder / "generated" / build["id"]),
                        "package": build["package"],
                        "version": build["version"],
                        "offline_dir": str(options["offline_dir"]) if options.get("offline_dir") else None,
                        "builder_settings": asdict(settings),
                    },
                    folder / "generated" / build["id"] / "worker",
                    deadline,
                    cancel,
                )
            finally:
                # Only the namespace reserved for this terminated child; never the shared scratch root.
                contained_path(base, scratch.name, must_exist=False)
                shutil.rmtree(scratch)
        else:
            value = asdict(
                self.builder.build(
                    build["url"],
                    folder / "generated" / build["id"],
                    build["package"],
                    build["version"],
                    cancel,
                    **options,
                )
            )
        artifact_path = value.pop("artifact_path", None)
        if cancel.is_set() or time.monotonic() >= deadline:
            value = {
                "state": "cancelled" if cancel.is_set() else "failed",
                "reason_code": "cancelled" if cancel.is_set() else "build_timeout",
            }
        artifacts: list[dict] = []
        if value.get("state") == "built" and artifact_path is not None:
            relative = str(Path(artifact_path).absolute().relative_to(self.store.root))
            contained_path(self.store.root, relative)
            artifacts.append(
                {
                    "job_id": build["job_id"],
                    "owner": build["owner"],
                    "build_id": build["id"],
                    "path": relative,
                    "filename": value.get("filename") or build["filename"],
                    "kind": "apk",
                    "sha256": value.get("sha256") or "",
                    "size": value.get("size") or 0,
                    "origin": "generated_webview",
                }
            )
        self.store.finish_with_artifacts(
            build["id"], value.get("state", "failed"), value, artifacts, deadline, cancel, build=True
        )

    def cleanup_images(self) -> None:
        with self.store.connect() as db:
            expired = list(db.execute("SELECT id,path FROM images WHERE expires<?", (time.time(),)))
            for row in expired:
                try:
                    contained_path(self.store.root, row["path"]).unlink()
                    contained_path(self.store.root, row["path"] + ".jpg", must_exist=False).unlink(
                        missing_ok=True
                    )
                except FxfetchError:
                    pass  # Already missing; never follow a replacement link.
                db.execute("DELETE FROM images WHERE id=?", (row["id"],))
