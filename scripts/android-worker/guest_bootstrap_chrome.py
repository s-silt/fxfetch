"""One bounded, offline stock-Chrome/CDP infrastructure check in the project VM."""

from __future__ import annotations

import json
import time

import guest_environment as env


def main() -> None:
    env.validate_vm()
    env.firewall()
    container_id = env.run("docker", "inspect", "--format", "{{.Id}}", env.NAME)
    timer_unit = f"fxfetch-chrome-check-{int(time.time())}"
    env.run("systemd-run", f"--unit={timer_unit}", "--on-active=600", "--timer-property=AccuracySec=1", "/usr/bin/docker", "stop", "--time", "5", container_id)
    env.run("docker", "start", container_id, timeout=60)
    env.namespace_firewall(expected_container_id=container_id)
    env.wait_for_boot(container_id=container_id)
    env.run("adb", "connect", "127.0.0.1:15600")
    flags = env.ROOT / "assets/chrome-command-line"
    flags.write_text("chrome --no-first-run --no-default-browser-check --disable-fre --disable-background-networking --disable-component-update --disable-sync --disable-quic --proxy-server=http://10.0.2.2:18767 --proxy-bypass-list=<-loopback> --remote-debugging-port=9222\n")
    env.run("adb", "-s", "127.0.0.1:15600", "push", str(flags), "/data/local/tmp/chrome-command-line")
    env.run("adb", "-s", "127.0.0.1:15600", "shell", "pm", "clear", "com.android.chrome")
    env.run("adb", "-s", "127.0.0.1:15600", "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", "about:blank", "-p", "com.android.chrome")
    env.run("adb", "-s", "127.0.0.1:15600", "forward", "tcp:9222", "localabstract:chrome_devtools_remote")
    ready = env.wait_for_cdp(container_id, expected_version="145.0.7632.218")
    print(json.dumps({**ready, "container_id": container_id, "timer_unit": timer_unit + ".timer", "production_enabled": False}))


if __name__ == "__main__":
    main()
