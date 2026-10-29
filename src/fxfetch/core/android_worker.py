"""One-task leases for the dedicated, independently guarded Android worker VM.

Only local administrator configuration selects the SSH key. Web input never
becomes an SSH command. A live root-owned guest helper verifies the environment
and installs its own deadline before granting a lease.
"""

from __future__ import annotations

import json
import queue
import re
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from typing import TYPE_CHECKING, Any

from .browser_gateway import BrowserGateway
from .errors import FxfetchError

if TYPE_CHECKING:
    from .browser_capture import BrowserLaunchProof

HELPER = "/opt/fxfetch/guest_session.py"
IMAGE = "sha256:11d58a64bfbde2253d1cce81bff409ff58174980222d1bada232d9ef59181191"
PROBE_ID = "0" * 32


@dataclass(frozen=True)
class AndroidWorkerConfig:
    key_path: Path
    known_hosts_path: Path
    helper_sha256: str
    chrome_source_sha256: str
    trichrome_source_sha256: str
    environment_sha256: str

    def __post_init__(self) -> None:
        for value in (
            self.helper_sha256,
            self.chrome_source_sha256,
            self.trichrome_source_sha256,
            self.environment_sha256,
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("invalid_worker_digest")
        for path in (self.key_path, self.known_hosts_path):
            if not path.is_absolute() or not path.is_file():
                raise ValueError("worker_key_or_known_hosts_missing")


def load_worker_config(root: Path) -> AndroidWorkerConfig | None:
    path = root / "android-worker.json"
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > 8192:
            raise ValueError("worker_configuration_limit")
        values = json.loads(path.read_text(encoding="utf-8"))
        return AndroidWorkerConfig(
            key_path=Path(values["key_path"]),
            known_hosts_path=Path(values["known_hosts_path"]),
            helper_sha256=values["helper_sha256"],
            chrome_source_sha256=values["chrome_source_sha256"],
            trichrome_source_sha256=values["trichrome_source_sha256"],
            environment_sha256=values["environment_sha256"],
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise FxfetchError("browser_worker_configuration", "Android worker configuration is invalid") from exc


class AndroidWorker:
    def __init__(self, config: AndroidWorkerConfig) -> None:
        self.config = config

    def _ssh(self) -> list[str]:
        executable = shutil.which("ssh")
        if executable is None:
            raise FxfetchError("browser_worker_unavailable", "OpenSSH client is unavailable")
        return [
            executable,
            "-T",
            "-p",
            "12222",
            "-i",
            str(self.config.key_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(self.config.known_hosts_path),
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
        ]

    def call(self, action: str, lease_id: str, timeout_seconds: int | None = None) -> dict[str, Any]:
        if action not in {"begin", "status", "end", "recover-idle"} or not re.fullmatch(r"[0-9a-f]{32}", lease_id):
            raise ValueError("invalid_worker_operation")
        if action == "recover-idle" and lease_id != PROBE_ID:
            raise ValueError("recovery_requires_probe_id")
        payload: dict[str, object] = {"lease_id": lease_id}
        if timeout_seconds is not None:
            if action != "begin" or not 1 <= timeout_seconds <= 600:
                raise ValueError("invalid_worker_deadline")
            payload["timeout_seconds"] = timeout_seconds
        # The only interpolated field is a validated hex digest; the command is
        # fixed. Target URLs, headers and credentials never enter this channel.
        command = (
            'test "$(sha256sum '
            + HELPER
            + " | cut -d ' ' -f 1)\" = "
            + self.config.helper_sha256
            + " && test \"$(sha256sum /opt/fxfetch/guest_environment.py | cut -d ' ' -f 1)\" = "
            + self.config.environment_sha256
            + " && sudo -n python3 "
            + HELPER
            + " "
            + action
        )
        try:
            completed = subprocess.run(
                [*self._ssh(), "worker@127.0.0.1", command],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                # Real cold starts can take ~149s. Preparation remains inside
                # the caller's lease and the service's hard task deadline.
                timeout=min(240, timeout_seconds or 240) if action == "begin" else {
                    "recover-idle": 60, "end": 30, "status": 45,
                }[action],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            code = "browser_worker_start_timeout" if action == "begin" else "browser_worker_unavailable"
            raise FxfetchError(code, "Android worker control deadline exceeded") from exc
        except OSError as exc:
            raise FxfetchError("browser_worker_unavailable", "Android worker did not answer") from exc
        if completed.returncode or len(completed.stdout) > 32768:
            raise FxfetchError("browser_worker_unavailable", "Android worker rejected its control request")
        try:
            result = json.loads(completed.stdout)
        except (ValueError, TypeError) as exc:
            raise FxfetchError("browser_worker_protocol", "Android worker returned invalid metadata") from exc
        if not isinstance(result, dict):
            raise FxfetchError("browser_worker_protocol", "Android worker returned invalid metadata")
        return result

    def validate(
        self,
        status: dict[str, Any],
        lease_id: str | None = None,
        *,
        readiness: bool = False,
    ) -> None:
        live_guard = status.get("guard_ready") is True
        verified_idle = (
            readiness and status.get("state") == "idle" and status.get("deployment_verified") is True
        )
        if (
            not (live_guard or verified_idle)
            or status.get("data_capacity_bytes") != 2 * 1024 * 1024 * 1024
            or status.get("image_digest") not in {IMAGE, "redroid/redroid@" + IMAGE}
            or status.get("chrome_package") != "com.android.chrome"
            or status.get("chrome_source_sha256") != self.config.chrome_source_sha256
            or status.get("trichrome_source_sha256") != self.config.trichrome_source_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", str(status.get("firewall_sha256", "")))
            or status.get("cdp_endpoint") != "http://127.0.0.1:9222"
        ):
            raise FxfetchError("browser_guard_unavailable", "Live Android confinement checks did not pass")
        if lease_id is not None and (
            status.get("lease_id") != lease_id
            or not isinstance(status.get("expires_at"), (int, float))
            or not time.time() < status["expires_at"] <= time.time() + 605
        ):
            raise FxfetchError("browser_guard_unavailable", "Android lease has expired or changed")

    def probe(self) -> dict[str, object]:
        try:
            status = self.call("status", PROBE_ID)
            self.validate(status, readiness=True)
            return {
                "enabled": True,
                "mode": "android_chrome",
                "device": "isolated_android",
                "version": str(status.get("chrome_version", ""))[:80],
            }
        except FxfetchError as exc:
            return {"enabled": False, "reason_code": exc.code}


class AndroidLease:
    def __init__(
        self, worker: AndroidWorker, gateway: BrowserGateway, cancel: Event, timeout: float,
        *, lease_id: str | None = None,
    ) -> None:
        self.worker, self.gateway, self.cancel = worker, gateway, cancel
        self.timeout = max(1, min(600, int(timeout)))
        if lease_id is not None and (
            not re.fullmatch(r"[0-9a-f]{32}", lease_id) or lease_id == PROBE_ID
        ):
            raise ValueError("invalid_worker_lease_id")
        self.lease_id = lease_id if lease_id is not None else uuid.uuid4().hex
        self.tunnel: subprocess.Popen | None = None
        self.status: dict[str, Any] = {}
        self.started = False

    def __enter__(self) -> AndroidLease:
        if not self.gateway.active or self.gateway.port != 18767 or self.cancel.is_set():
            raise FxfetchError("browser_guard_unavailable", "Direct egress gate is not active")
        # Close even after ambiguous begin: the guest may have accepted a lease
        # whose SSH response was lost. Its independent timer is the final guard.
        self.started = True
        try:
            self.status = self.worker.call("begin", self.lease_id, self.timeout)
            self.worker.validate(self.status, self.lease_id)
            self.tunnel = subprocess.Popen(
                [
                    *self.worker._ssh(),
                    "-L",
                    "127.0.0.1:19222:127.0.0.1:9222",
                    "-o",
                    "ExitOnForwardFailure=yes",
                    "worker@127.0.0.1",
                    # SSH runs this fixed command only after successfully
                    # installing its forwarding listeners. Merely connecting to
                    # an occupied local port could attach the wrong browser.
                    "/usr/bin/python3 -u -c 'import sys; print(\"FXFETCH_TUNNEL_READY\"); sys.stdin.read()'",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            ready: queue.Queue[bytes] = queue.Queue(maxsize=1)
            stream = self.tunnel.stdout
            assert stream is not None
            Thread(target=lambda: ready.put(stream.readline(64)), daemon=True).start()
            forwarding_confirmed = False
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if self.tunnel.poll() is not None or self.cancel.is_set():
                    break
                if not forwarding_confirmed:
                    try:
                        line = ready.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    if line != b"FXFETCH_TUNNEL_READY\n":
                        break
                    forwarding_confirmed = True
                try:
                    with socket.create_connection(("127.0.0.1", 19222), timeout=0.25):
                        return self
                except OSError:
                    self.cancel.wait(0.1)
            raise FxfetchError("browser_worker_unavailable", "Local Android CDP tunnel did not start")
        except (FxfetchError, OSError):
            self.close()
            raise

    def verify_before_launch(self) -> BrowserLaunchProof:
        from .browser_capture import BrowserLaunchProof

        try:
            if (
                not self.started
                or not self.gateway.active
                or self.cancel.is_set()
                or self.tunnel is None
                or self.tunnel.poll() is not None
            ):
                raise FxfetchError("browser_guard_unavailable", "Android lease is no longer active")
            self.status = self.worker.call("status", self.lease_id)
            self.worker.validate(self.status, self.lease_id)
            # Status can take time. Cancellation or a lost tunnel during that
            # control request must not arm the new task's data plane.
            if self.cancel.is_set() or self.tunnel.poll() is not None:
                raise FxfetchError("browser_guard_unavailable", "Android lease changed during verification")
            self.gateway.arm(self.lease_id)
        except FxfetchError:
            self.gateway.close()
            raise
        return BrowserLaunchProof(
            executable_path=Path("/system/bin/chrome"),
            profile_root=Path("/data"),
            proxy_server="http://10.0.2.2:18767",
            cdp_endpoint="http://127.0.0.1:19222",
            permit_request=lambda url, method: self.gateway.permit_request(self.lease_id, url, method),
        )

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        # Cut the data plane before waiting for SSH/guest cleanup. A hung control
        # channel must never extend the target's network activity.
        self.gateway.close()
        if self.tunnel is not None:
            self.tunnel.terminate()
            try:
                self.tunnel.wait(3)
            except subprocess.TimeoutExpired:
                self.tunnel.kill()
                self.tunnel.wait(3)
            for stream in (self.tunnel.stdin, self.tunnel.stdout):
                if stream is not None:
                    stream.close()
            self.tunnel = None
        if self.started:
            self.started = False
            try:
                self.worker.call("end", self.lease_id)
            except FxfetchError:
                # Do not replace a validated package outcome with cleanup I/O.
                # The gate is already closed. The guest timer independently
                # force-stops Chrome after the granted deadline.
                raise
