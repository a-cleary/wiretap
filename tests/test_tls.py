from datetime import datetime, timezone

from wiretap.capture.tls import (
    tls_client_hello_from_packet,
    tls_server_hello_from_packet,
)
from wiretap.models import (
    TLSClientHello,
    TLSServerHello,
)


def test_tls_client_hello_model():
    timestamp = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    hello = TLSClientHello(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=443,
        version="TLS 1.2",
        server_name="example.com",
        alpn_protocols=["h2", "http/1.1"],
        cipher_suites=[
            "0xc02f",
            "0xc02b",
        ],
    )

    assert hello.source_ip == "10.10.10.42"
    assert hello.destination_port == 443
    assert hello.version == "TLS 1.2"
    assert hello.server_name == "example.com"
    assert hello.alpn_protocols == [
        "h2",
        "http/1.1",
    ]


def test_tls_server_hello_model():
    timestamp = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    hello = TLSServerHello(
        timestamp=timestamp,
        source_ip="10.10.10.20",
        source_port=443,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="TLS 1.2",
        cipher_suite="0xc02f",
        alpn_protocol="h2",
    )

    assert hello.source_ip == "10.10.10.20"
    assert hello.destination_ip == "10.10.10.42"
    assert hello.version == "TLS 1.2"
    assert hello.cipher_suite == "0xc02f"
    assert hello.alpn_protocol == "h2"


def test_non_tls_packet_returns_none():
    from scapy.layers.inet import IP, TCP

    packet = IP(
        src="10.10.10.42",
        dst="10.10.10.20",
    ) / TCP(
        sport=49152,
        dport=443,
    )

    assert (
        tls_client_hello_from_packet(packet)
        is None
    )

    assert (
        tls_server_hello_from_packet(packet)
        is None
    )