"""Private one-task subprocess. HTTP callers cannot select its operation or configuration."""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import asdict
from pathlib import Path

from .core.limits import Limits
from .core.network import AcquisitionPolicy
from .core.proxy import LocalConnectProxy
from .core.task_evidence_recorder import TaskEvidenceRecorder
from .core.tls_policy import web_tls_policy
from .core.web_apk import WebApkBuilder, WebApkSettings
from .store import Store, json_text

_PATHS = {
    "sdk_root",
    "java_home",
    "build_tools_root",
    "signing_keystore",
    "signing_password_file",
    "scratch_root",
    "offline_font_path",
    "offline_font_license_path",
}


def main() -> int:
    request_path, result_path = map(Path, sys.argv[1:3])
    request = json.loads(request_path.read_text(encoding="utf-8"))
    store = Store(Path(request["root"]))
    build = request["operation"] == "build"

    def progress(event: dict) -> None:
        store.progress(request["identifier"], event, build=build)

    if build:
        settings = request["builder_settings"]
        for name in _PATHS:
            if settings.get(name) is not None:
                settings[name] = Path(settings[name])
        builder = WebApkBuilder(WebApkSettings(**settings))
        result = builder.build(
            request["url"],
            Path(request["output_dir"]),
            request["package"],
            request["version"],
            threading.Event(),
            offline_dir=Path(request["offline_dir"]) if request.get("offline_dir") else None,
            on_event=progress,
        )
    else:
        tls_policy = web_tls_policy({key: request[key] for key in ('tls_policy', 'ignore_tls_errors') if key in request}
                                    or {'tls_policy': 'strict'})
        limits = Limits(**request["limits"])
        output_dir = Path(request["output_dir"])
        recorder = TaskEvidenceRecorder(
            output_dir,
            Path(request["observation_path"]) if request.get("observation_path") else None,
        )
        recorder.append('task_tls_policy', {'tls_policy': tls_policy})
        proxy = (
            LocalConnectProxy(request["proxy_host"], request["proxy_port"])
            if request.get("proxy_host")
            else None
        )
        workflow = AcquisitionPolicy(
            limits, proxy, browser_root=Path(request["root"]),
            android_lease_id=request.get("android_lease_id"),
            transport_observer=recorder,
            tls_policy=tls_policy,
        )
        try:
            result = workflow.run(request["url"], output_dir, threading.Event(), progress)
        finally:
            recorder.close()
    pending = result_path.with_suffix(".pending")
    pending.write_text(json_text(asdict(result)), encoding="utf-8")
    pending.replace(result_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
