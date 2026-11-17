"""Fresh guest provisioning contracts without Docker, VM or network access."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


def module():
    path = Path(__file__).resolve().parents[1] / "scripts/windows-installer/provision_guest.py"
    spec = importlib.util.spec_from_file_location("installer_provision", path)
    assert spec and spec.loader
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_seed_contains_fresh_pinned_keys_and_no_old_runtime() -> None:
    provisioning = module()
    text = provisioning.cloud_config("ssh-ed25519 SYNTHETICCLIENT", "SYNTHETICPRIVATE\n", "ssh-ed25519 SYNTHETICHOST")
    config = json.loads(text.split("\n", 1)[1])
    assert config["ssh_keys"]["ed25519_private"] == "SYNTHETICPRIVATE\n"
    assert config["users"][0]["ssh_authorized_keys"] == ["ssh-ed25519 SYNTHETICCLIENT"]
    assert config["package_upgrade"] is False
    assert "android-data.ext4" not in text and "acceptance.json" not in text
    assert "PermitRootLogin no" in text


def test_offline_seed_never_updates_or_installs_packages() -> None:
    provisioning = module()
    text = provisioning.cloud_config("synthetic client", "synthetic private", "synthetic host", offline=True)
    config = json.loads(text.split("\n", 1)[1])
    assert config["package_update"] is False and config["package_upgrade"] is False
    assert "packages" not in config
    assert all(command[0] not in {"apt", "apt-get", "curl", "wget"} and "pull" not in command for command in config["runcmd"])
    assert ["systemctl", "mask", "--now", "apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service", "apt-daily-upgrade.service"] in config["runcmd"]


def test_template_hash_is_checked_before_identity_creation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provisioning = module()
    (tmp_path / "ubuntu-prepared.qcow2").write_bytes(b"changed template")
    (tmp_path / "ubuntu-prepared.json").write_text(json.dumps({
        "scope": "fresh_software_only_template", "source_sha256": provisioning.UBUNTU_SHA256,
        "free_space_trimmed": True,
        "template_sha256": "0" * 64}), encoding="utf-8")
    calls = []
    monkeypatch.setattr(provisioning, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(RuntimeError, match="provision_asset_hash_mismatch"):
        provisioning.prepare(tmp_path, tmp_path / "guest")
    assert not calls and not (tmp_path / "guest").exists()


def test_existing_guest_refused_before_any_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provisioning = module()
    state = tmp_path / "已有 guest"
    state.mkdir()
    calls = []
    monkeypatch.setattr(provisioning, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(RuntimeError, match="fresh_guest_state_must_not_exist"):
        provisioning.prepare(tmp_path, state, "fixed-local-image")
    assert calls == []


def test_wrong_cloud_source_rejected_without_state_or_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provisioning = module()
    (tmp_path / "noble-server-cloudimg-amd64.vmdk").write_bytes(b"untrusted")
    calls = []
    monkeypatch.setattr(provisioning, "run", lambda *args, **kwargs: calls.append(args))
    state = tmp_path / "new guest"
    with pytest.raises(RuntimeError, match="provision_asset_hash_mismatch"):
        provisioning.prepare(tmp_path, state, "fixed-local-image")
    assert not state.exists() and calls == []


def test_bootstrap_rejects_shell_container_and_old_marker(tmp_path: Path) -> None:
    provisioning = module()
    with pytest.raises(ValueError, match="invalid_new_worker_container"):
        provisioning.bootstrap(tmp_path, tmp_path, tmp_path / "api", "worker;echo", tmp_path)
    (tmp_path / "provision.json").write_text('{"state":"synthetic_acceptance_passed"}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="fresh_disk_marker_required"):
        provisioning.bootstrap(tmp_path, tmp_path, tmp_path / "api", "new-worker", tmp_path)


def test_download_asset_symlinks_are_rejected(tmp_path: Path) -> None:
    provisioning = module()
    actual = tmp_path / "actual"
    actual.write_bytes(b"synthetic")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(actual)
    except OSError:
        pytest.skip("symlink permission unavailable")
    with pytest.raises(RuntimeError, match="provision_asset_missing_or_link"):
        provisioning.verify(alias, "0" * 64)


def test_preparation_uses_new_identity_and_offline_conversion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provisioning = module()
    calls = []

    def fake_run(arguments, timeout=120):
        calls.append(arguments)
        if "ssh-keygen" in arguments:
            mount = next(value for value in arguments if value.startswith("type=bind,") and value.endswith("target=/state"))
            state = Path(mount.removeprefix("type=bind,source=").removesuffix(",target=/state"))
            destination = state / Path(arguments[-1]).name
            destination.write_text("SYNTHETIC PRIVATE", encoding="utf-8")
            destination.with_suffix(".pub").write_text("ssh-ed25519 SYNTHETIC PUBLIC", encoding="utf-8")
        return ""

    monkeypatch.setattr(provisioning, "run", fake_run)
    monkeypatch.setattr(provisioning, "verify", lambda *args: None)
    monkeypatch.setattr(provisioning, "private_directory", lambda path: path.mkdir())
    monkeypatch.setattr(provisioning, "write_seed", lambda path, *args: path.write_bytes(b"SYNTHETIC ISO"))
    states = [tmp_path / "中文 path 1", tmp_path / "中文 path 2"]
    for state in states:
        provisioning.prepare(tmp_path, state)
    first, second = [json.loads((state / "identity.json").read_text(encoding="utf-8")) for state in states]
    assert first["uuid"] != second["uuid"] and first["mac"] != second["mac"]
    assert first["mac"].startswith("02:")
    conversions = [call for call in calls if "convert" in call]
    assert len(conversions) == 2
    assert all("none" in call and "never" in call for call in conversions)
    assert any("中文 path 1" in argument for argument in conversions[0])
    assert all("root.qcow2" in call[-1] for call in conversions)
    assert "[127.0.0.1]:12222 ssh-ed25519 SYNTHETIC PUBLIC" in (states[0] / "known_hosts").read_text(encoding="utf-8")


def test_interrupted_conversion_resumes_only_owned_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provisioning = module()
    state = tmp_path / "中文 interrupted guest"
    fail_once = True
    active_mount = False
    new_keys = []

    def fake_run(arguments, timeout=120):
        nonlocal fail_once
        if arguments[:3] == ["docker", "ps", "-q"]:
            return "synthetic-container" if active_mount else ""
        if arguments[:2] == ["docker", "inspect"]:
            return json.dumps([{"Mounts": [{"Type": "bind", "Source": str(state)}]}])
        if "ssh-keygen" in arguments:
            if "-y" in arguments:
                return "ssh-ed25519 SYNTHETIC"
            destination = state / Path(arguments[-1]).name
            destination.write_text("SYNTHETIC PRIVATE", encoding="utf-8")
            destination.with_suffix(".pub").write_text("ssh-ed25519 SYNTHETIC", encoding="utf-8")
            new_keys.append(destination.name)
        if "convert" in arguments:
            (state / "root.qcow2").write_bytes(b"partial" if fail_once else b"complete")
            if fail_once:
                fail_once = False
                raise RuntimeError("synthetic_conversion_interrupted")
        return ""

    def create_private(path):
        assert path.with_name(path.name + ".prepare-owner.json").is_file()
        path.mkdir()

    monkeypatch.setattr(provisioning, "run", fake_run)
    monkeypatch.setattr(provisioning, "verify", lambda *args: None)
    monkeypatch.setattr(provisioning, "private_directory", create_private)
    monkeypatch.setattr(provisioning, "protect_directory", lambda path: None)
    monkeypatch.setattr(provisioning, "write_seed", lambda path, *args: path.write_bytes(b"SYNTHETIC ISO"))
    with pytest.raises(RuntimeError, match="synthetic_conversion_interrupted"):
        provisioning.prepare(tmp_path, state)
    owner = json.loads(state.with_name(state.name + ".prepare-owner.json").read_text(encoding="utf-8"))
    assert (state / "root.qcow2").read_bytes() == b"partial"
    assert not (state / "provision.json").exists()
    active_mount = True
    with pytest.raises(RuntimeError, match="owned_partial_state_is_still_in_use"):
        provisioning.prepare(tmp_path, state)
    assert (state / "root.qcow2").read_bytes() == b"partial"
    active_mount = False
    provisioning.prepare(tmp_path, state)
    receipt = json.loads((state / "provision.json").read_text(encoding="utf-8"))
    assert receipt["instance_id"] == owner["instance_id"]
    assert (state / "root.qcow2").read_bytes() == b"complete"
    assert new_keys == ["worker_ed25519", "ssh_host_ed25519_key"]


def test_guest_baseline_copy_is_exclusive_and_preserves_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "path", sys.path.copy())
    for name in ("guest_environment", "guest_bootstrap_chrome", "guest_disk_acceptance", "guest_install_chrome", "guest_session"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    path = Path(__file__).resolve().parents[1] / "scripts/windows-installer/guest_bootstrap.py"
    spec = importlib.util.spec_from_file_location("installer_guest_bootstrap_test", path)
    assert spec and spec.loader
    guest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guest)
    active, base = tmp_path / "active.ext4", tmp_path / "baseline.ext4"
    active.write_bytes(b"synthetic freshly cleared data" * 100)
    guest.copy_baseline(active, base)
    assert base.read_bytes() == active.read_bytes()
    active.write_bytes(b"different synthetic data")
    with pytest.raises(FileExistsError):
        guest.copy_baseline(active, base)
    assert base.read_bytes() != active.read_bytes()
