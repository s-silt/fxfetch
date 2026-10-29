from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from fxfetch import cli
from fxfetch.core.workflow import WorkflowResult
from fxfetch.security import password_matches


def test_default_url_preview_never_resolves_or_creates_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_: object, **__: object) -> None:
        pytest.fail("offline preview attempted networking")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(cli.Workflow, "run", forbidden)
    output = tmp_path / "never_created"
    assert cli.main(["https://synthetic.invalid/app.apk?secret=synthetic", "--out", str(output)]) == 0
    printed = capsys.readouterr().out
    state = json.loads(printed)
    assert state["mode"] == "offline" and state["host"] == "synthetic.invalid"
    assert state["network_requests"] == 0 and state["outcome"] is None
    assert "secret" not in printed
    assert not output.exists()


def test_active_flag_is_required_for_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[str] = []

    def run(self: object, url: str, *args: object) -> WorkflowResult:
        received.append(url)
        return WorkflowResult("not_found", "synthetic_complete", "complete")

    monkeypatch.setattr(cli.Workflow, "run", run)
    assert cli.main(["https://synthetic.invalid/", "--out", str(tmp_path)]) == 0
    assert not received
    assert cli.main(["https://synthetic.invalid/", "--out", str(tmp_path), "--authorized-active"]) == 0
    assert received == ["https://synthetic.invalid/"]


def test_init_interactive_private_hash_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    password = "synthetic-test-password"
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: password)

    def private(path: Path) -> bool:
        path.mkdir(parents=True)
        return True

    monkeypatch.setattr(cli, "_private_directory", private)
    root = tmp_path / "service"
    assert cli.main(["init", "--out", str(root)]) == 0
    encoded = json.loads((root / "auth.json").read_text())["password_hash"]
    assert password_matches(password, encoded)
    assert not password_matches("wrong", encoded)
    printed = capsys.readouterr().out
    assert password not in printed and encoded not in printed
    assert cli.main(["init", "--out", str(root)]) == 1
    assert json.loads((root / "auth.json").read_text())["password_hash"] == encoded


@pytest.mark.parametrize("values", [["short", "short"], ["long-enough-password", "another-password"]])
def test_init_invalid_password_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, values: list[str]
) -> None:
    entered = iter(values)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(entered))
    assert cli.main(["init", "--out", str(tmp_path)]) == 1
    assert not (tmp_path / "auth.json").exists()


@pytest.mark.parametrize(
    "host,extra",
    [
        ("0.0.0.0", []),
        ("::", []),
        ("127.0.0.1", ["*:8765"]),
        ("127.0.0.1", ["example.invalid"]),
        ("127.0.0.1", ["example.invalid:8766"]),
    ],
)
def test_unsafe_bind_allowlist_rejected(host: str, extra: list[str]) -> None:
    with pytest.raises(ValueError):
        cli._allowed_hosts(host, 8765, extra)


def test_explicit_lan_hosts_and_wildcard_rejection() -> None:
    assert cli._allowed_hosts("192.168.1.2", 8765, []) == ("192.168.1.2:8765",)
    with pytest.raises(ValueError):
        cli._allowed_hosts("0.0.0.0", 8765, ["192.168.1.2:8765"])
    with pytest.raises(ValueError):
        cli._allowed_hosts("::1", 8765, [])


def test_serve_single_worker_no_access_log_or_proxy_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    monkeypatch.setattr(cli, "_load_auth", lambda _: "synthetic stored hash")
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(uvicorn, "run", lambda *_, **kwargs: calls.append(kwargs))
    assert cli.main(["serve", "--out", str(tmp_path)]) == 0
    assert calls[0]["workers"] == 1
    assert calls[0]["access_log"] is False
    assert calls[0]["proxy_headers"] is False
    assert calls[0]["host"] == "127.0.0.1"


def test_doctor_no_secret_or_tool_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["doctor", "--out", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    parsed = json.loads(output)
    assert parsed["network_requests"] == 0
    assert "tools" not in parsed["web_apk"]
    assert "password_hash" not in output and "JAVA_HOME" not in output


def test_server_file_and_explicit_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    saved = {
        "host": "192.168.12.2",
        "port": 8765,
        "allowed_networks": ["192.168.12.0/24", "127.0.0.0/8"],
        "proxy_host": "127.0.0.1",
        "proxy_port": 7890,
    }
    (tmp_path / "server.json").write_text(json.dumps(saved))
    monkeypatch.setattr(cli, "_load_auth", lambda _: "synthetic stored hash")
    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda *_, **kwargs: calls.append(kwargs))
    assert cli.main(["serve", "--out", str(tmp_path)]) == 0
    assert calls[-1]["host"] == "192.168.12.2"
    assert cli.main(["serve", "--out", str(tmp_path), "--host", "127.0.0.1", "--port", "8766"]) == 0
    assert calls[-1]["host"] == "127.0.0.1" and calls[-1]["port"] == 8766
    assert cli._server_config(tmp_path)["allowed_networks"] == ("192.168.12.0/24", "127.0.0.0/8")


@pytest.mark.parametrize(
    "saved",
    [
        {"host": "0.0.0.0"},
        {"host": "8.8.8.8"},
        {"allowed_networks": ["0.0.0.0/0"]},
        {"allowed_networks": "127.0.0.0/8"},
        {"proxy_host": "192.168.1.2"},
        {"port": True},
        {"unrecognized": True},
    ],
)
def test_server_file_invalid_fails_closed(tmp_path: Path, saved: dict) -> None:
    (tmp_path / "server.json").write_text(json.dumps(saved))
    assert cli.main(["serve", "--out", str(tmp_path)]) == 1


def test_active_cli_uses_explicit_public_dns_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    supplied: list[object] = []
    sentinel = object()
    monkeypatch.setattr(cli, "build_default_client", lambda *args: supplied.append(args) or sentinel)

    class SyntheticWorkflow:
        def __init__(self, *, client: object, limits: object) -> None:
            assert client is sentinel

        def run(self, *args: object) -> WorkflowResult:
            return WorkflowResult("not_found", "synthetic_complete", "complete")

    monkeypatch.setattr(cli, "Workflow", SyntheticWorkflow)
    assert (
        cli.main(
            [
                "https://synthetic.invalid/",
                "--out",
                str(tmp_path),
                "--authorized-active",
                "--proxy-host",
                "127.0.0.1",
                "--proxy-port",
                "7890",
            ]
        )
        == 0
    )
    assert supplied and supplied[0][1] is None
