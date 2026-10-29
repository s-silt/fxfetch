"""Guest-only synthetic bridge probes; never edits either firewall.

The live-lease test executes this source in the dedicated VM. A temporary
namespace/veth exercises the outer guard without weakening Android's inner
guard. Destinations are fixed local addresses and a test-only broker.
"""

from __future__ import annotations

import json
import socket
import subprocess
import threading
import uuid


def run(*args: str, timeout: float = 5) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=timeout).stdout.strip()


def drops(chain: str) -> int:
    content = json.loads(run("nft", "-j", "list", "chain", "inet", "fxfetch_android", chain))
    counters = []
    for item in content["nftables"]:
        expressions = item.get("rule", {}).get("expr", [])
        if any("drop" in expression for expression in expressions):
            counters.extend(expression["counter"]["packets"] for expression in expressions if "counter" in expression)
    if len(counters) != 1:
        raise RuntimeError("Expected exactly one outer drop counter per chain")
    return counters[0]


def main() -> None:
    if socket.gethostname() != "fxfetch-android-worker":
        raise RuntimeError("Dedicated VM only")
    network = json.loads(run("docker", "network", "inspect", "fxfetch-android-net"))[0]
    if network["Options"].get("com.docker.network.bridge.name") != "fxfetch-and":
        raise RuntimeError("Unexpected bridge")
    if any(row.get("IPv4Address", "").split("/")[0] == "172.30.0.254" for row in network.get("Containers", {}).values()):
        raise RuntimeError("Probe address already allocated")
    suffix = uuid.uuid4().hex[:8]
    namespace, host, peer = "fxop-" + suffix, "fxoh-" + suffix, "fxon-" + suffix
    created_namespace = created_link = False
    rows = []
    received = threading.Event()
    stop = threading.Event()
    with socket.socket() as canary:
        canary.bind(("172.30.0.1", 0))
        canary.listen(1)
        canary.settimeout(0.1)

        def accept_canary() -> None:
            while not stop.is_set():
                try:
                    connection, _ = canary.accept()
                    received.set()
                    connection.close()
                except TimeoutError:
                    continue

        thread = threading.Thread(target=accept_canary, daemon=True)
        thread.start()
        try:
            # UUID names must be absent. Never delete another task's namespace.
            existing = json.loads(run("ip", "-j", "netns", "list") or "[]")
            if any(item["name"] == namespace for item in existing):
                raise RuntimeError("Probe namespace already exists")
            run("ip", "netns", "add", namespace)
            created_namespace = True
            run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
            created_link = True
            run("ip", "link", "set", peer, "netns", namespace)
            run("ip", "link", "set", host, "master", "fxfetch-and")
            run("ip", "link", "set", host, "up")
            run("ip", "-n", namespace, "link", "set", "lo", "up")
            run("ip", "-n", namespace, "addr", "add", "172.30.0.254/24", "dev", peer)
            run("ip", "-n", namespace, "link", "set", peer, "up")
            run("ip", "-n", namespace, "route", "add", "default", "via", "172.30.0.1")
            for chain, address, port in [
                ("input", "172.30.0.1", canary.getsockname()[1]),
                ("forward", "10.0.2.2", 12222),
            ]:
                before = drops(chain)
                code = (
                    "import socket,json; s=socket.socket(); s.settimeout(1); "
                    f"result=s.connect_ex(({address!r},{port})); "
                    "print(json.dumps({'connect_errno':result})); s.close()"
                )
                row = json.loads(run("ip", "netns", "exec", namespace, "python3", "-c", code))
                delta = drops(chain) - before
                rows.append({"chain": chain, "address": address, "drop_packets_delta": delta,
                             "canary_received": received.is_set(), **row,
                             "passed": row["connect_errno"] != 0 and delta > 0 and not received.is_set()})
            code = (
                "import http.client,json; c=http.client.HTTPConnection('10.0.2.2',18767,timeout=3); "
                "c.request('GET','http://capture.test/empty'); r=c.getresponse(); "
                "print(json.dumps({'status':r.status,'bytes':len(r.read(1024))})); c.close()"
            )
            broker = json.loads(run("ip", "netns", "exec", namespace, "python3", "-c", code))
            rows.append({"route": "broker", **broker, "passed": broker["status"] == 200})
        finally:
            stop.set()
            thread.join(1)
            try:
                if created_link:
                    run("ip", "link", "delete", host)
            finally:
                if created_namespace:
                    run("ip", "netns", "delete", namespace)
    print(json.dumps({"status": "passed" if all(row["passed"] for row in rows) else "failed",
                      "scope": "outer_bridge_local_synthetic_only", "rows": rows,
                      "temporary_namespace_removed": True, "temporary_veth_removed": True}))


if __name__ == "__main__":
    main()
