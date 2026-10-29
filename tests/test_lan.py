import ipaddress

import pytest

from fxfetch.core.lan import client_allowed, excluded_ipv4_networks, validate_bind, validate_lan_networks


@pytest.mark.parametrize('network', ['0.0.0.0/0', '8.8.8.0/24', '198.18.0.0/15', '169.254.0.0/16', '224.0.0.0/4', '::/0', '192.168.1.1/24'])
def test_reject_unsafe_network(network):
    with pytest.raises(ValueError):
        validate_lan_networks((network,))


def test_private_networks_and_transport_peers():
    networks = validate_lan_networks(('192.168.12.0/24', '127.0.0.0/8'))
    for peer in ('192.168.12.9', '127.0.0.1', '::ffff:192.168.12.9'):
        assert client_allowed(peer, networks)
    for peer in ('192.168.13.9', '8.8.8.8', '::1', None, '192.168.12.9, 8.8.8.8', 'localhost'):
        assert not client_allowed(peer, networks)


@pytest.mark.parametrize('address', ['0.0.0.0', '::', '::1', 'example.test', '8.8.8.8', '169.254.1.2', '198.18.1.2'])
def test_reject_unsafe_bind(address):
    with pytest.raises(ValueError):
        validate_bind(address)


def test_concrete_private_bind_and_loopback():
    assert validate_bind('192.168.12.2') == '192.168.12.2'
    assert validate_bind('127.0.0.1') == '127.0.0.1'


def test_complement_exact_and_disjoint():
    allowed = ('192.168.12.0/24', '127.0.0.0/8', '192.168.12.0/25')
    complement = tuple(ipaddress.IPv4Network(item) for item in excluded_ipv4_networks(allowed))
    expected = tuple(ipaddress.IPv4Network(item) for item in allowed[:2])
    assert all(not left.overlaps(right) for left in complement for right in expected)
    assert sum(item.num_addresses for item in complement + expected) == 2**32
    assert any(ipaddress.IPv4Address('8.8.8.8') in item for item in complement)


def test_invalid_or_empty_policy_fails_closed():
    assert not client_allowed('192.168.1.1', ())
    assert not client_allowed('192.168.1.1', ('0.0.0.0/0',))
