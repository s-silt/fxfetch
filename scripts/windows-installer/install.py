"""Offline, restartable Windows deployment. No acquisition or package execution.

Only this reviewed entrypoint is called by Setup.exe. All payload paths/hashes are
checked before dependencies are changed. Credentials arrive through stdin only.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

READINESS = """
import json
from pathlib import Path
from fxfetch.core.android_worker import AndroidWorker, load_worker_config
from fxfetch.build_setup import load_builder
root = Path('/var/lib/fxfetch')
config = load_worker_config(root)
chrome = AndroidWorker(config).probe() if config else {'enabled': False}
build = load_builder(root).probe()
print(json.dumps({'chrome': chrome.get('enabled') is True, 'web_apk': build.enabled}))
"""


def emit(status: str, message: str, **values: object) -> None:
    print(json.dumps({"status": status, "message": message, **values}, ensure_ascii=False), flush=True)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(path: Path) -> None:
    reject_reparse(path)
    if not path.is_file():
        raise ValueError("payload_file_missing")


def reject_reparse(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink() or (part.exists() and getattr(part.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError("reparse_path_rejected")


def existing_file_matches(target: Path, expected: str, mismatch: str) -> bool:
    reject_reparse(target)
    if not target.exists():
        return False
    if not target.is_file() or sha(target) != expected:
        raise ValueError(mismatch)
    return True


def install_verified_file(source: Path, target: Path, expected: str, mismatch: str) -> None:
    if existing_file_matches(target, expected, mismatch):
        return
    regular(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".installing-", dir=target.parent, delete=False) as stream:
            temporary = Path(stream.name)
            with source.open("rb") as input_stream:
                shutil.copyfileobj(input_stream, stream)
        if sha(temporary) != expected:
            raise ValueError("copied_payload_digest_mismatch")
        if not existing_file_matches(target, expected, mismatch):
            # Windows rename also refuses an existing destination if it appeared
            # after the check. Never open a destination or fixed .installing path for writing.
            if os.name == "nt":
                temporary.rename(target)
            else:
                os.link(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def verify_bundle(bundle: Path) -> dict:
    manifest = bundle / "manifest.json"
    regular(manifest)
    if manifest.stat().st_size > 16 * 1024**2:
        raise ValueError("manifest_size_limit")
    data = json.loads(manifest.read_text(encoding="utf-8-sig"))
    if data.get("schema") != "fxfetch.offline-install.v1" or not isinstance(data.get("files"), list):
        raise ValueError("invalid_payload_manifest")
    if not 10 <= len(data["files"]) <= 50000:
        raise ValueError("invalid_payload_inventory")
    names: set[str] = set()
    for item in data["files"]:
        name = item["path"]
        if not isinstance(name, str) or "\\" in name or ":" in name or any(p in {"", ".", ".."} for p in name.split("/")):
            raise ValueError("invalid_payload_path")
        path = bundle / name
        if path.is_absolute() and not path.resolve().is_relative_to(bundle.resolve()):
            raise ValueError("payload_path_outside_bundle")
        if name.casefold() in names:
            raise ValueError("duplicate_payload_path")
        names.add(name.casefold())
        regular(path)
        if path.stat().st_size != item["bytes"] or sha(path) != item["sha256"]:
            raise ValueError("payload_digest_mismatch")
    required = {"assets/docker-desktop-installer.exe", "assets/wsl.msi", "assets/docker-images.tar",
                "assets/ubuntu-prepared.qcow2", "assets/ubuntu-prepared.json", "runtime/python.exe",
                "app/scripts/windows-installer/prerequisites.ps1", "fxfetch.exe", "fxfetch-setup.exe",
                "assets/android-sdk-linux/platforms/android-35/android.jar",
                "assets/android-sdk-linux/build-tools/37.0.0/aapt2", "assets/android-sdk-linux/build-tools/37.0.0/zipalign",
                "assets/android-sdk-linux/build-tools/37.0.0/apksigner", "assets/android-sdk-linux/build-tools/37.0.0/d8",
                "assets/fonts/notosanscjksc-regular-sans2.004.otf", "assets/fonts/notosanscjksc-regular-sans2.004.license.txt",
                "assets/licenses/docker-license.rtf"}
    if not required <= names:
        raise ValueError("incomplete_offline_payload")
    return data


def run(args: list[str], timeout: int = 60, *, payload: dict | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    # Windows PowerShell must construct its own module search path when this
    # installer was launched from PowerShell 7. Do not modify the machine env.
    environment = {key: value for key, value in environment.items() if key.casefold() != "psmodulepath"}
    result = subprocess.run(args, input=None if payload is None else json.dumps(payload, ensure_ascii=False),
                            capture_output=True, text=True, encoding="utf-8", errors="replace", env=environment,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=timeout)
    if len(result.stdout) + len(result.stderr) > 8 * 1024**2:
        raise ValueError("local_output_limit")
    if check and result.returncode:
        raise ValueError("local_command_failed")
    return result


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("local_module_missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def docker_path() -> str:
    candidates = [shutil.which("docker"),
                  str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Docker/Docker/resources/bin/docker.exe"),
                  str(Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            os.environ["PATH"] = str(Path(candidate).parent) + os.pathsep + os.environ.get("PATH", "")
            return candidate
    raise ValueError("docker_cli_missing")


def copy_payload(bundle: Path, root: Path, manifest: dict) -> None:
    if root == bundle:
        # A copied, verified installation can resume from its own Setup.exe
        # after reboot. An unpacked distribution is not an owned installation.
        owned = root / "private/installation.json"
        regular(owned)
        installed_manifest = root / "manifest.json"
        regular(installed_manifest)
        if json.loads(owned.read_text(encoding="utf-8")).get("manifest_sha256") != sha(installed_manifest):
            raise ValueError("same_directory_resume_identity_mismatch")
        return
    if root.is_relative_to(bundle) or bundle.is_relative_to(root):
        raise ValueError("install_root_must_be_separate_from_bundle")
    private = root / "private"
    for part in (private, root, *root.parents):
        if part.exists() and (part.is_symlink() or getattr(part.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError("reparse_installation_directory_rejected")
    marker = private / "installation.json"
    journal = root / ".installation-preparing.json"
    source_manifest, installed_manifest = bundle / "manifest.json", root / "manifest.json"
    regular(source_manifest)
    with source_manifest.open("rb") as stream:
        manifest_bytes = stream.read(16 * 1024**2 + 1)
    if len(manifest_bytes) > 16 * 1024**2 or json.loads(manifest_bytes.decode("utf-8-sig")) != manifest:
        raise ValueError("bundle_manifest_changed")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    manifest_mismatch = "existing_installed_manifest_changed"
    existing_file_matches(installed_manifest, manifest_hash, manifest_mismatch)
    if marker.exists():
        regular(marker)
        if json.loads(marker.read_text(encoding="utf-8")).get("manifest_sha256") != manifest_hash:
            raise ValueError("existing_installation_requires_separate_upgrade")
    else:
        if journal.exists():
            regular(journal)
            initial = json.loads(journal.read_text(encoding="utf-8"))
            if initial.get("manifest_sha256") != manifest_hash or not re.fullmatch(r"[0-9a-f]{32}", initial.get("install_id", "")):
                raise ValueError("installation_preparation_identity_mismatch")
            if any(p.name not in {journal.name, "private"} for p in root.iterdir()) or (private.exists() and any(private.iterdir())):
                raise ValueError("unexpected_preparation_files_preserved")
        else:
            if root.exists() and any(root.iterdir()):
                raise ValueError("installation_directory_not_empty")
            root.mkdir(parents=True, exist_ok=True)
            initial = {"manifest_sha256": manifest_hash, "install_id": uuid.uuid4().hex}
            with journal.open("x", encoding="utf-8") as stream:
                json.dump(initial, stream)
        sid = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                   "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"]).stdout.strip()
        if not re.fullmatch(r"S-1-(?:\d+-)+\d+", sid):
            raise ValueError("windows_owner_invalid")
        private.mkdir(parents=True, exist_ok=True)
        run(["icacls.exe", str(private), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"])
        # Atomic rename leaves either the preparation journal or the final
        # marker, never a half-written JSON identity after interruption.
        journal.replace(marker)
    for item in manifest["files"]:
        source, target = bundle / item["path"], root / item["path"]
        install_verified_file(source, target, item["sha256"], "existing_installed_file_changed")
    install_verified_file(source_manifest, installed_manifest, manifest_hash, manifest_mismatch)


def launch(root: Path) -> str:
    metadata = root / "private/launcher.json"
    regular(metadata)
    config = json.loads(metadata.read_text(encoding="utf-8"))
    helper = root / "app/scripts/android-worker/start_docker.py"
    docker = docker_path()
    emit("starting", "正在启动 Docker 并检查局域网防火墙及现有服务……")
    output = run([sys.executable, "-X", "utf8", "-u", str(helper), "--env-file", str(root / "private/runtime.env"),
                  "--override", str(root / "app/deploy/android-docker/compose.build.yaml"),
                  "--override", str(root / "private/runtime.yaml"), "--lan-subnet", config["subnet"]], 540, check=False)
    rows = [json.loads(line) for line in output.stdout.splitlines() if line.startswith("{")]
    if output.returncode or not any(row.get("phase") == "containers_healthy" for row in rows):
        reason = next((row.get("reason") for row in reversed(rows) if row.get("phase") == "failed"), "startup_failed")
        emit("failed", "服务启动未完成：" + str(reason))
        raise ValueError("service_startup_failed")
    # Match the actual storage, not just a similarly named project's port/image.
    identity = json.loads((root / "private/service-install.json").read_text(encoding="utf-8"))
    for role, destination, expected in (("api", "/var/lib/fxfetch", identity["volume"]),
                                         ("android-worker", "/state", str(root / "private/guest"))):
        ids = run([docker, "ps", "-q", "--filter", "label=com.docker.compose.project=fxfetch-android-docker",
                   "--filter", "label=com.docker.compose.service=" + role]).stdout.splitlines()
        if len(ids) != 1:
            raise ValueError("running_installation_identity_missing")
        actual = json.loads(run([docker, "inspect", ids[0]]).stdout)[0]
        mounts = [m for m in actual["Mounts"] if m["Destination"] == destination]
        if len(mounts) != 1:
            raise ValueError("running_installation_storage_mismatch")
        if role == "api":
            matches = mounts[0].get("Name") == expected
        else:
            matches = os.path.normcase(str(Path(mounts[0]["Source"]).resolve())) == os.path.normcase(str(Path(expected).resolve()))
        if not matches:
            raise ValueError("running_installation_storage_mismatch")
        if role == "api":
            readiness = json.loads(run([docker, "exec", ids[0], "python", "-c", READINESS], 65).stdout)
            if readiness != {"chrome": True, "web_apk": True}:
                raise ValueError("installed_features_not_ready")
    publication = next(row["publication"] for row in rows if row.get("phase") == "configuration_verified")
    return "http://" + publication + "/"


def install(args: argparse.Namespace, secret: dict) -> int:
    bundle, root = args.bundle.resolve(), args.root.absolute()
    if os.name != "nt":
        raise ValueError("windows_only")
    if root.anchor.startswith("\\\\") or not root.drive:
        raise ValueError("local_windows_installation_directory_required")
    emit("verifying", "正在校验完整离线安装包，大镜像校验需要几分钟……")
    manifest = verify_bundle(bundle)
    if any(c in str(root) for c in (",", "\r", "\n")):
        raise ValueError("installation_path_contains_unsupported_separator")
    if secret.get("use_default") is True:
        defaults = json.loads((bundle / "defaults.json").read_text(encoding="utf-8-sig"))
        if not re.fullmatch(r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", defaults.get("password_hash", "")):
            raise ValueError("invalid_default_password_hash")
    elif not isinstance(secret.get("password"), str) or not 12 <= len(secret["password"]) <= 1024:
        raise ValueError("invalid_custom_password")
    # Literal LAN settings only; never bind all interfaces or infer a public origin.
    sys.path.insert(0, str(bundle / "app/src"))
    from fxfetch.core.lan import validate_bind, validate_lan_networks
    ip = validate_bind(args.lan_ip)
    subnet = validate_lan_networks((args.subnet,))[0]
    if ipaddress.ip_address(ip).is_loopback or ipaddress.ip_address(ip) not in ipaddress.ip_network(subnet):
        raise ValueError("invalid_lan_selection")
    if not args.accept_licenses:
        raise ValueError("license_acceptance_required")
    if shutil.disk_usage(root.anchor).free < 60 * 1024**3 and not (root / "private/installation.json").exists():
        raise ValueError("at_least_60_gib_free_required")
    emit("copying", "正在复制安装文件，保留安装进度供重启后继续……")
    copy_payload(bundle, root, manifest)
    scripts = root / "app/scripts/windows-installer"
    try:
        run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(scripts / "shortcut.ps1"),
             "-InstallRoot", str(root), "-Mode", "Setup"], 20)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        emit("notice", "未创建续装快捷方式；重启后可运行安装目录中的 fxfetch-setup.exe。")
    emit("prerequisites", "正在离线配置 WSL 和 Docker，系统可能要求重启……")
    output = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(scripts / "prerequisites.ps1"),
                  "-InstallRoot", str(root), "-AssetsDirectory", str(root / "assets"), "-AcceptDockerLicense"], 2400, check=False)
    if output.returncode == 20:
        emit("reboot_required", "依赖已配置，需要重启。重启后再次运行同一安装程序，选择相同安装目录即可继续。")
        return 20
    if output.returncode:
        rows = [json.loads(line) for line in output.stdout.splitlines() if line.startswith("{")]
        status = rows[-1].get("status") if rows else "failed"
        explanations = {
            "unsupported_windows": "需要受支持的 Windows 11 x64 系统（内部版本 22631 及以上）。",
            "virtualization_required": "硬件虚拟化未启用或不受支持；请检查 BIOS/UEFI 的虚拟化设置。",
            "insufficient_memory": "系统内存不足，无法启动完整 Android 环境。",
            "admin_required": "需要 Windows 管理员授权，请运行随包的安装程序。",
            "offline_windows_feature_install_failed": "本机 Windows 组件安装失败；不会联网补齐，请检查 private 中的系统组件日志。",
            "wsl_install_failed": "WSL 离线安装未完成，请检查 private 中的安装日志。",
            "docker_install_failed": "Docker 离线安装未完成，请检查 private 中的安装日志。",
        }
        emit("failed", explanations.get(status, "系统依赖未满足，请查看安装目录 private 中的诊断。"), prerequisites=rows)
        return 1
    docker = docker_path()
    starter = load("installer_docker_start", root / "app/scripts/android-worker/start_docker.py")
    starter.ensure_engine(docker)
    starter.ensure_kvm(shutil.which("wsl") or "wsl.exe")
    # This installer never adopts or replaces another project already on this PC.
    existing = run([docker, "ps", "-aq", "--filter", "label=com.docker.compose.project=fxfetch-android-docker"]).stdout.strip()
    if existing:
        if (root / "private/launcher.json").exists():
            emit("ready", "已有安装，启动并检查服务。", url=launch(root))
            return 0
        raise ValueError("another_fxfetch_deployment_exists")
    emit("images", "正在从本地导入容器镜像，不访问镜像仓库……")
    run([docker, "image", "load", "--input", str(root / "assets/docker-images.tar")], 1800)
    for name, identifier in manifest["images"].items():
        if run([docker, "image", "inspect", name, "--format", "{{.Id}}"]).stdout.strip() != identifier:
            raise ValueError("imported_image_identity_mismatch")
    guest = load("provision_guest", scripts / "provision_guest.py")
    state = root / "private/guest"
    emit("android", "正在建立独立 Android 环境并执行隔离、下载及超时验收……")
    guest.prepare(root / "assets", state)
    identifier = json.loads((root / "private/installation.json").read_text(encoding="utf-8"))["install_id"]
    network, worker = "fxfetch-install-" + identifier, "fxfetch-install-worker-" + identifier
    # Temporary worker has no published host ports. It is not the production service.
    inspection = run([docker, "network", "inspect", network], check=False)
    if inspection.returncode:
        run([docker, "network", "create", "--internal", "--label", "io.fxfetch.install-id=" + identifier,
             "--subnet", "172.30.247.0/28", network])
    else:
        inspected_network = json.loads(inspection.stdout)[0]
        if inspected_network.get("Labels", {}).get("io.fxfetch.install-id") != identifier or inspected_network.get("Internal") is not True:
            raise ValueError("temporary_network_identity_mismatch")
    inspection = run([docker, "container", "inspect", worker], check=False)
    if not inspection.returncode:
        document = json.loads(inspection.stdout)[0]
        if document.get("Config", {}).get("Labels", {}).get("io.fxfetch.install-id") != identifier:
            raise ValueError("temporary_worker_identity_mismatch")
        if not document["State"]["Running"]:
            run([docker, "start", worker])
    else:
        run([docker, "run", "-d", "--pull", "never", "--name", worker, "--label", "io.fxfetch.install-id=" + identifier,
             "--network", network, "--ip", "172.30.247.2", "--device", "/dev/kvm:/dev/kvm", "--read-only",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "6g",
             "--memory-swap", "6g", "--cpus", "2", "--tmpfs", "/run/fxfetch:size=4m,mode=0700",
             "--tmpfs", "/tmp:size=16m", "--mount", f"type=bind,source={state},target=/state",
             "fxfetch-android-qemu:local"])
    guest.bootstrap(root / "assets", state, root / "private/api-worker", worker, root / "app")
    # Stop only the known installer-owned temporary worker after all gates pass.
    run([docker, "stop", "--time", "45", worker], 65)
    stopped = json.loads(run([docker, "inspect", worker]).stdout)[0]
    if stopped["State"]["Running"] or stopped["State"]["ExitCode"] == 137:
        raise ValueError("guest_shutdown_not_clean")
    run([docker, "rm", worker])
    run([docker, "network", "rm", network])
    service = load("service_setup", scripts / "service_setup.py")
    if secret.get("use_default") is True:
        defaults = json.loads((root / "defaults.json").read_text(encoding="utf-8-sig"))
        service.initialise(docker, root, password_hash=defaults["password_hash"])
    else:
        service.initialise(docker, root, password=secret["password"])
    service.write_runtime_config(root, ip, subnet, 8765)
    emit("firewall", "正在配置仅允许所选局域网访问的防火墙规则……")
    run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(root / "app/scripts/configure-docker-lan.ps1"),
         "-LanIP", ip, "-Subnet", subnet, "-Port", "8765", "-PythonPath", sys.executable], 90)
    (root / "private/launcher.json").write_text(json.dumps({"subnet": subnet}), encoding="utf-8")
    url = launch(root)
    try:
        run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(scripts / "shortcut.ps1"),
             "-InstallRoot", str(root)], 20)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        emit("notice", "桌面快捷方式未创建；可直接运行安装目录中的 fxfetch.exe。")
    emit("ready", "离线安装及本机验收完成。请在另一台局域网设备验证访问和文件下载。", url=url)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("install", "launch", "verify"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--lan-ip")
    parser.add_argument("--subnet")
    parser.add_argument("--accept-licenses", action="store_true")
    args = parser.parse_args()
    if args.mode == "verify":
        verify_bundle(args.bundle.resolve())
        emit("verified", "离线包文件校验通过；尚未更改本机或启动服务。")
        return 0
    if args.mode == "launch":
        emit("ready", "服务检查通过。", url=launch(args.root.resolve()))
        return 0
    line = sys.stdin.readline(8193)
    if len(line) > 8192:
        raise ValueError("credential_input_limit")
    # .NET Framework redirected stdin can emit a UTF-8 BOM even when the
    # subsequent StreamWriter uses BOM-free UTF-8. Accept only the leading BOM.
    return install(args, json.loads(line.removeprefix("\ufeff")))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.TimeoutExpired) as error:
        reason = str(error)
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,100}", reason):
            reason = "offline_installation_step_failed"
        emit("failed", "未完成：" + reason + "。已保留本机配置及安装进度，不会自动重试目标网址。")
        raise SystemExit(1) from None
