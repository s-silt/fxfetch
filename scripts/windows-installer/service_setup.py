"""Fresh local API identity and Compose settings; never copy a previous instance."""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import uuid
from pathlib import Path

IMAGE = "fxfetch-android-api-builder:local"
LABEL = "io.fxfetch.install-id"

# This constant is reviewed installer code, not supplied by a web page or user.
# Credentials travel only in stdin, never argv, Docker environment or Compose.
INITIALIZER = r'''
import hmac, json, os, re, subprocess, sys
from pathlib import Path
from fxfetch.security import password_hash, password_matches
from fxfetch.build_setup import setup_build, _FONT_PINS
p = json.load(sys.stdin)
analysis = Path('/opt/fxapk-venv/bin/fxapk')
if not analysis.is_file() or not os.access(analysis, os.X_OK):
    raise ValueError('bundled_offline_analysis_missing')
probe = subprocess.run([str(analysis), '--version'], capture_output=True, text=True, encoding='utf-8', timeout=20)
if probe.returncode or not probe.stdout.strip().startswith('fxapk '):
    raise ValueError('bundled_offline_analysis_unavailable')
encoded = p.get('password_hash')
if encoded is not None and (not isinstance(encoded, str) or not re.fullmatch(r'pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}', encoded)):
    raise ValueError('invalid_auth_configuration')
r = Path('/var/lib/fxfetch')
os.chmod(r, 0o700)
marker = r / '.installer-identity.json'
if marker.exists():
    if json.loads(marker.read_text(encoding='utf-8')) != {'install_id': p['install_id']}:
        raise ValueError('volume_identity_mismatch')
else:
    if any(r.iterdir()):
        raise ValueError('fresh_volume_not_empty')
    with marker.open('x', encoding='utf-8') as f:
        json.dump({'install_id': p['install_id']}, f)
auth = r / 'auth.json'
if auth.exists():
    stored = json.loads(auth.read_text(encoding='utf-8'))
    matches = hmac.compare_digest(encoded, stored['password_hash']) if encoded is not None else password_matches(p['password'], stored['password_hash'])
    if not matches:
        raise ValueError('resume_password_mismatch')
else:
    with auth.open('x', encoding='utf-8') as f:
        json.dump({'password_hash': encoded if encoded is not None else password_hash(p['password'])}, f)
os.chmod(auth, 0o600)
source = Path('/installer-worker')
def bounded_file(name, limit):
    path = source / name
    if path.is_symlink() or not path.is_file():
        raise ValueError('worker_source_not_regular')
    with path.open('rb') as stream:
        value = stream.read(limit + 1)
    if not value or len(value) > limit:
        raise ValueError('worker_source_size_invalid')
    return value
accepted = json.loads(bounded_file('provision-acceptance.json', 16384))
if accepted.get('state') != 'synthetic_acceptance_passed':
    raise ValueError('worker_acceptance_required')
values = {name: bounded_file(name, limit) for name, limit in (
    ('android-worker.json', 8192), ('worker_ed25519', 16384), ('known_hosts', 65536))}
configuration = json.loads(values['android-worker.json'])
digests = {'helper_sha256', 'chrome_source_sha256', 'trichrome_source_sha256', 'environment_sha256'}
if set(configuration) != digests | {'key_path', 'known_hosts_path'} or any(
    not isinstance(configuration[k], str) or not re.fullmatch(r'[0-9a-f]{64}', configuration[k]) for k in digests
):
    raise ValueError('worker_configuration_invalid')
if configuration['key_path'] != '/run/fxfetch-worker/worker_ed25519' or configuration['known_hosts_path'] != '/run/fxfetch-worker/known_hosts':
    raise ValueError('worker_configuration_path_invalid')
destination = r / 'worker-config'
if destination.is_symlink():
    raise ValueError('worker_destination_invalid')
destination.mkdir(mode=0o700, exist_ok=True)
for name, value in values.items():
    target = destination / name
    pending = destination / (name + '.installing')
    if target.is_symlink() or pending.is_symlink():
        raise ValueError('worker_destination_invalid')
    with pending.open('wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(pending, 0o600)
    pending.replace(target)
fonts = Path('/opt/fonts')
fontfiles = [x for x in fonts.iterdir() if x.is_file() and x.suffix.lower() in {'.otf', '.ttf'}]
licenses = [x for x in fonts.iterdir() if x.is_file() and (x.name.lower() in {'ofl.txt', 'license', 'license.txt'} or x.name.lower().endswith('.license.txt'))]
if len(fontfiles) != 1 or len(licenses) != 1:
    raise ValueError('font_assets_ambiguous_or_missing')
config = {'path': str(fontfiles[0]), 'license_path': str(licenses[0]), **_FONT_PINS}
(r / 'offline-font.json').write_text(json.dumps(config), encoding='utf-8')
result = setup_build(r, Path('/opt/android-sdk'), Path('/opt/android-sdk/build-tools/37.0.0'), Path('/opt/java'))
if result.state != 'ready':
    raise ValueError('offline_build_setup_not_ready')
for folder, dirs, files in os.walk(r):
    os.chown(folder, 10001, 10001)
    os.chmod(folder, 0o700)
    for name in files:
        path = Path(folder) / name
        if path.is_symlink():
            raise ValueError('unexpected_volume_symlink')
        os.chown(path, 10001, 10001)
        os.chmod(path, 0o600)
print(json.dumps({'state':'ready','build':'ready','fresh_identity':True}))
'''


def run(docker: str, arguments: list[str], *, payload: dict | None = None,
        timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [docker, *arguments], input=None if payload is None else json.dumps(payload, ensure_ascii=False),
        capture_output=True, text=True, encoding="utf-8", errors="strict", timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise RuntimeError("service_setup_output_limit")
    if check and result.returncode:
        # Docker diagnostics and container traceback can disclose private paths.
        raise RuntimeError("service_setup_command_failed")
    return result


def _root(root: Path) -> Path:
    root = root.absolute()
    if any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError("installation_root_must_not_be_link")
    return root


def _marker(root: Path) -> tuple[Path, dict]:
    path = root / "private/service-install.json"
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("installation_marker_must_not_be_link")
    if path.exists():
        if not path.is_file() or path.stat().st_size > 4096:
            raise ValueError("installation_marker_invalid")
        document = json.loads(path.read_text(encoding="utf-8"))
        if set(document) != {"schema", "install_id", "volume"} or document["schema"] != "fxfetch.service-install.v1":
            raise ValueError("installation_marker_invalid")
        identifier = uuid.UUID(document["install_id"]).hex
        if document["volume"] != "fxfetch-api-" + identifier:
            raise ValueError("installation_volume_identity_invalid")
        return path, document
    path.parent.mkdir(parents=True, exist_ok=True)
    identifier = uuid.uuid4()
    document = {"schema": "fxfetch.service-install.v1", "install_id": str(identifier),
                "volume": "fxfetch-api-" + identifier.hex}
    with path.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, ensure_ascii=False)
    return path, document


def initialise(docker: str, root: Path, password: str | None = None, *, password_hash: str | None = None) -> dict:
    """Initialize only a new or marker-owned volume using offline local assets."""
    root = _root(root)
    if (password is None) == (password_hash is None):
        raise ValueError("exactly_one_password_or_hash_required")
    if password_hash is not None:
        # Exact format from fxfetch.cli._load_auth; no attacker-selected costs.
        if not isinstance(password_hash, str) or not re.fullmatch(r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", password_hash):
            raise ValueError("invalid_auth_configuration")
        credentials = {"password_hash": password_hash}
    else:
        if not isinstance(password, str) or len(password) < 12 or len(password) > 1024 or "\0" in password:
            raise ValueError("service_password_requires_12_to_1024_characters")
        credentials = {"password": password}
    for directory in (root / "assets/android-sdk-linux", root / "assets/fonts", root / "private/api-worker"):
        if directory.is_symlink() or not directory.is_dir() or "," in str(directory):
            raise ValueError("service_asset_directory_invalid")
    _, identity = _marker(root)
    volume = identity["volume"]
    # List-before-inspect distinguishes a missing volume from daemon/permission errors.
    volumes = run(docker, ["volume", "ls", "--format", "{{.Name}}"])
    if volume not in volumes.stdout.splitlines():
        run(docker, ["volume", "create", "--label", f"{LABEL}={identity['install_id']}", volume])
    inspected = json.loads(run(docker, ["volume", "inspect", volume]).stdout)
    if not isinstance(inspected, list) or len(inspected) != 1 or (inspected[0].get("Labels") or {}).get(LABEL) != identity["install_id"]:
        raise ValueError("refuse_unowned_existing_api_volume")
    arguments = ["run", "--rm", "-i", "--network", "none", "--pull", "never", "--user", "0:0",
                 "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
                 "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges:true",
                 "--pids-limit", "128", "--memory", "2g", "--memory-swap", "2g",
                 "--tmpfs", "/tmp:rw,size=128m,nosuid,nodev",
                 "--mount", f"type=volume,source={volume},target=/var/lib/fxfetch"]
    for source, target in (("android-sdk-linux", "/opt/android-sdk"), ("fonts", "/opt/fonts")):
        arguments += ["--mount", f"type=bind,source={root / 'assets' / source},target={target},readonly"]
    arguments += ["--mount", f"type=bind,source={root / 'private/api-worker'},target=/installer-worker,readonly"]
    arguments += ["--entrypoint", "python", IMAGE, "-c", INITIALIZER]
    result = run(docker, arguments, payload={"install_id": identity["install_id"], **credentials}, timeout=180)
    status = json.loads(result.stdout)
    if status != {"state": "ready", "build": "ready", "fresh_identity": True}:
        raise RuntimeError("service_initialization_unverified")
    return {**status, "volume": volume}


def write_runtime_config(root: Path, lan_ip: str, subnet: str, port: int = 8765) -> dict:
    """Write overrides consumed with the shipped base and build Compose files."""
    root = _root(root)
    ip = ipaddress.IPv4Address(lan_ip)
    network = ipaddress.IPv4Network(subnet, strict=True)
    private = [ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not any(ip in value and network.subnet_of(value) for value in private) or ip not in network or ip in (network.network_address, network.broadcast_address):
        raise ValueError("explicit_private_lan_address_and_subnet_required")
    if isinstance(port, bool) or not 1024 <= port <= 65535 or port in {12222, 19222, 18767}:
        raise ValueError("invalid_api_port")
    _, identity = _marker(root)
    private_root = root / "private"
    env_file, override = private_root / "runtime.env", private_root / "runtime.yaml"
    if env_file.is_symlink() or override.is_symlink():
        raise ValueError("runtime_configuration_must_not_be_link")
    environment = {"FXFETCH_ANDROID_STATE": str(root / "private/guest"),
                   "FXFETCH_ANDROID_CONFIG_DIR": str(root / "private/api-worker"),
                   "FXFETCH_LINUX_SDK": str(root / "assets/android-sdk-linux"),
                   "FXFETCH_FONTS": str(root / "assets/fonts"),
                   "FXFETCH_FXAPK": "/opt/fxapk-venv/bin/fxapk",
                   "FXFETCH_DNS_PROVIDERS": "cloudflare,google"}
    # Compose single quotes preserve spaces, Unicode, dollars and Windows backslashes.
    if any("\n" in value or "\r" in value for value in environment.values()):
        raise ValueError("invalid_installation_path")
    env_file.write_text("".join(key + "='" + value.replace("'", "\\'") + "'\n" for key, value in environment.items()), encoding="utf-8")
    api_environment = {"FXFETCH_PUBLIC_IP": str(ip), "FXFETCH_PORT": str(port),
                       "FXFETCH_TRUSTED_PEERS": "172.30.247.1/32," + str(network)}
    # !override is essential: merge semantics would retain the default loopback port.
    document = ("services:\n  android-worker:\n    ports: !override\n"
                f"      - {json.dumps({'target': port, 'published': str(port), 'host_ip': str(ip), 'protocol': 'tcp'})}\n"
                "  api:\n    environment: " + json.dumps(api_environment) + "\n"
                "    volumes: !override\n"
                "      - {type: volume, source: api-state, target: /var/lib/fxfetch}\n"
                "      - {type: volume, source: api-state, target: /run/fxfetch-worker, read_only: true, volume: {subpath: worker-config, nocopy: true}}\n"
                "      - {type: bind, source: '${FXFETCH_LINUX_SDK}', target: /opt/android-sdk, read_only: true, bind: {create_host_path: false}}\n"
                "      - {type: bind, source: '${FXFETCH_FONTS}', target: /opt/fonts, read_only: true, bind: {create_host_path: false}}\n"
                "volumes:\n  api-state:\n    external: true\n    name: " + json.dumps(identity["volume"]) + "\n")
    override.write_text(document, encoding="utf-8")
    return {"env_file": str(env_file), "override": str(override), "volume": identity["volume"],
            "publication": f"{ip}:{port}", "lan_subnet": str(network)}
