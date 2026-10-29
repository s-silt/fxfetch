"""Fixed local connection probes; run only inside the isolated Android netns."""
import json
import socket
import subprocess


def drop_count():
    result = subprocess.run(
        ['nft', '-j', 'list', 'table', 'inet', 'fxfetch_browser_output'],
        check=True, capture_output=True, text=True, timeout=3,
    )
    rules = json.loads(result.stdout)['nftables']
    counts = []
    for item in rules:
        rule = item.get('rule', {})
        expressions = rule.get('expr', [])
        if any('drop' in expression for expression in expressions):
            counts.extend(expression['counter']['packets'] for expression in expressions if 'counter' in expression)
    if len(counts) != 1:
        raise RuntimeError('expected_exact_namespace_drop_counter')
    return counts[0]


def main() -> None:
    rows = []
    for family, address, kind in [
        (socket.AF_INET, '127.0.0.1', socket.SOCK_STREAM),
        (socket.AF_INET, '172.30.0.2', socket.SOCK_STREAM),
        (socket.AF_INET6, '::1', socket.SOCK_STREAM),
        (socket.AF_INET, '127.0.0.1', socket.SOCK_DGRAM),
        (socket.AF_INET6, '::1', socket.SOCK_DGRAM),
    ]:
        with socket.socket(family, kind) as canary:
            canary.bind((address, 0))
            canary.settimeout(0.15)
            if kind == socket.SOCK_STREAM:
                canary.listen(1)
            port = canary.getsockname()[1]
            before = drop_count()
            with socket.socket(family, kind) as client:
                client.settimeout(0.7)
                result = 'unexpected_success'
                try:
                    if kind == socket.SOCK_STREAM:
                        client.connect((address, port))
                    else:
                        client.sendto(b'local-synthetic-canary', (address, port))
                        client.recv(1)
                except OSError as error:
                    result = type(error).__name__
            received = False
            try:
                if kind == socket.SOCK_STREAM:
                    accepted, _ = canary.accept()
                    accepted.close()
                else:
                    canary.recvfrom(64)
                received = True
            except TimeoutError:
                pass
            delta = drop_count() - before
            rows.append({'address': address, 'protocol': 'tcp' if kind == socket.SOCK_STREAM else 'udp',
                         'canary_received': received, 'drop_packets_delta': delta, 'connect_result': result,
                         'passed': not received and delta > 0 and result != 'unexpected_success'})

    for address, port, kind in [
        ('127.0.0.11', 53, socket.SOCK_DGRAM),
        ('172.30.0.1', 22, socket.SOCK_STREAM),
        ('10.0.2.2', 12222, socket.SOCK_STREAM),
    ]:
        before = drop_count()
        with socket.socket(socket.AF_INET, kind) as client:
            client.settimeout(0.7)
            result = 'unexpected_success'
            try:
                if kind == socket.SOCK_STREAM:
                    client.connect((address, port))
                else:
                    # Too short to be a DNS header: never submits a DNS question.
                    client.sendto(b'x', (address, port))
                    client.recv(1)
            except OSError as error:
                result = type(error).__name__
        delta = drop_count() - before
        rows.append({'address': address, 'port': port, 'protocol': 'tcp' if kind == socket.SOCK_STREAM else 'udp',
                     'drop_packets_delta': delta, 'connect_result': result,
                     'passed': delta > 0 and result != 'unexpected_success'})

    print(json.dumps({'status': 'passed' if all(row['passed'] for row in rows) else 'failed',
                      'scope': 'actual_android_network_namespace_local_synthetic_only', 'rows': rows}))


if __name__ == "__main__":
    main()
