from datetime import datetime, timezone

from wiretap.capture.tls_transactions import (
    TLSFlowKey,
    TLSTransactionTracker,
)
from wiretap.models import (
    TLSClientHello,
    TLSServerHello,
)


def _client_hello():
    return TLSClientHello(
        timestamp=datetime(
            2026,
            1,
            1,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=443,
        version="TLS 1.2",
        server_name="example.com",
        alpn_protocols=["h2"],
        cipher_suites=["0xc02f"],
    )


def _server_hello():
    return TLSServerHello(
        timestamp=datetime(
            2026,
            1,
            1,
            12,
            0,
            1,
            tzinfo=timezone.utc,
        ),
        source_ip="10.10.10.20",
        source_port=443,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="TLS 1.2",
        cipher_suite="0xc02f",
        alpn_protocol="h2",
    )


def test_flow_key_reverses_server_hello():
    client = _client_hello()
    server = _server_hello()

    client_key = TLSFlowKey.from_client_hello(
        client
    )

    server_key = TLSFlowKey.from_server_hello(
        server
    )

    assert client_key == server_key


def test_client_and_server_hello_are_correlated():
    tracker = TLSTransactionTracker()

    tracker.add_client_hello(
        _client_hello()
    )

    tracker.add_server_hello(
        _server_hello()
    )

    transactions = tracker.transactions()

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.client_hello is not None
    assert transaction.server_hello is not None

    assert (
        transaction.client_hello.server_name
        == "example.com"
    )

    assert (
        transaction.server_hello.cipher_suite
        == "0xc02f"
    )


def test_unmatched_server_hello_is_retained():
    tracker = TLSTransactionTracker()

    tracker.add_server_hello(
        _server_hello()
    )

    transactions = tracker.transactions()

    assert len(transactions) == 1
    assert transactions[0].client_hello is None
    assert transactions[0].server_hello is not None


def test_pending_client_hello():
    tracker = TLSTransactionTracker()

    hello = _client_hello()

    tracker.add_client_hello(hello)

    pending = tracker.pending_client_hellos()

    assert pending == [hello]