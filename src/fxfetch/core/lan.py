"""Literal IPv4 LAN policy, based only on the socket peer address."""

from __future__ import annotations

import ipaddress

_PRIVATE = tuple(ipaddress.IPv4Network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")


def validate_lan_networks(networks: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize explicit RFC1918/IPv4-loopback subnets, rejecting broad aggregates."""
    if not networks:
        raise ValueError("at least one explicit LAN subnet is required")
    result: list[str] = []
    for value in networks:
        network = ipaddress.ip_network(value, strict=True)
        if not isinstance(network, ipaddress.IPv4Network) or not any(
            network.subnet_of(allowed) for allowed in (*_PRIVATE, _LOOPBACK)
        ):
            raise ValueError("only RFC1918 and IPv4 loopback subnets are allowed")
        if str(network) not in result:
            result.append(str(network))
    return tuple(result)


def validate_bind(address: str) -> str:
    """Require a concrete IPv4 private/loopback interface, never a wildcard or DNS."""
    value = ipaddress.ip_address(address)
    if not isinstance(value, ipaddress.IPv4Address) or not any(
        value in allowed for allowed in (*_PRIVATE, _LOOPBACK)
    ):
        raise ValueError("bind must be a literal RFC1918 or IPv4 loopback address")
    return str(value)


def client_allowed(peer: str | None, networks: tuple[str, ...]) -> bool:
    """Use the transport peer only; callers must not supply forwarded-header values."""
    if peer is None:
        return False
    try:
        allowed = validate_lan_networks(networks)
        address = ipaddress.ip_address(peer)
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped is None:
                return False
            address = address.ipv4_mapped
        return any(address in ipaddress.IPv4Network(item) for item in allowed)
    except ValueError:
        return False


def excluded_ipv4_networks(networks: tuple[str, ...]) -> tuple[str, ...]:
    """Return the exact IPv4 complement for narrowly scoped firewall block rules."""
    allowed = [ipaddress.IPv4Network(item) for item in validate_lan_networks(networks)]
    remaining = [ipaddress.IPv4Network("0.0.0.0/0")]
    for network in ipaddress.collapse_addresses(allowed):
        next_remaining: list[ipaddress.IPv4Network] = []
        for candidate in remaining:
            if candidate.subnet_of(network):
                continue
            if network.subnet_of(candidate):
                next_remaining.extend(candidate.address_exclude(network))
            else:
                next_remaining.append(candidate)
        remaining = next_remaining
    return tuple(str(item) for item in sorted(remaining))
