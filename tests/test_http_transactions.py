from datetime import datetime, timedelta, timezone

from wiretap.capture.http_transactions import (
    HTTPFlowKey,
    HTTPTransactionTracker,
)
from wiretap.models import HTTPRequest, HTTPResponse


def make_request(
    timestamp: datetime,
    source_port: int = 49152,
    path: str = "/admin/login",
) -> HTTPRequest:
    return HTTPRequest(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=source_port,
        destination_ip="10.10.10.20",
        destination_port=80,
        method="GET",
        host="fileserver.corp.local",
        path=path,
        version="HTTP/1.1",
        user_agent="WiretapTest/1.0",
    )


def make_response(
    timestamp: datetime,
    destination_port: int = 49152,
    status_code: int = 200,
) -> HTTPResponse:
    return HTTPResponse(
        timestamp=timestamp,
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=destination_port,
        version="HTTP/1.1",
        status_code=status_code,
        reason="OK",
        server="nginx/1.24.0",
        content_type="text/html",
        content_length=18432,
        location=None,
    )


def test_http_flow_key_request_and_response_match():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request = make_request(timestamp)
    response = make_response(
        timestamp + timedelta(seconds=1)
    )

    request_key = HTTPFlowKey.from_request(request)
    response_key = HTTPFlowKey.from_response(response)

    assert request_key == response_key


def test_http_transaction_tracker_correlates_request_and_response():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request = make_request(timestamp)

    response = make_response(
        timestamp + timedelta(seconds=1)
    )

    tracker = HTTPTransactionTracker()

    tracker.add_request(request)
    tracker.add_response(response)

    transactions = tracker.transactions()

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.request is request
    assert transaction.response is response


def test_http_transaction_tracker_handles_unmatched_request():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request = make_request(timestamp)

    tracker = HTTPTransactionTracker()

    tracker.add_request(request)

    assert tracker.transactions() == []

    pending = tracker.pending_requests()

    assert len(pending) == 1
    assert pending[0] is request


def test_http_transaction_tracker_handles_unmatched_response():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    response = make_response(timestamp)

    tracker = HTTPTransactionTracker()

    tracker.add_response(response)

    transactions = tracker.transactions()

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.request is None
    assert transaction.response is response


def test_http_transaction_tracker_handles_multiple_requests():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request_one = make_request(
        timestamp,
        path="/admin",
    )

    request_two = make_request(
        timestamp + timedelta(seconds=1),
        path="/login",
    )

    response_one = make_response(
        timestamp + timedelta(seconds=2),
        status_code=200,
    )

    response_two = make_response(
        timestamp + timedelta(seconds=3),
        status_code=404,
    )

    tracker = HTTPTransactionTracker()

    tracker.add_request(request_one)
    tracker.add_request(request_two)

    tracker.add_response(response_one)
    tracker.add_response(response_two)

    transactions = tracker.transactions()

    assert len(transactions) == 2

    assert transactions[0].request is request_one
    assert transactions[0].response is response_one

    assert transactions[1].request is request_two
    assert transactions[1].response is response_two


def test_http_transaction_tracker_keeps_connections_separate():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request_one = make_request(
        timestamp,
        source_port=49152,
        path="/one",
    )

    request_two = make_request(
        timestamp + timedelta(seconds=1),
        source_port=49153,
        path="/two",
    )

    response_one = make_response(
        timestamp + timedelta(seconds=2),
        destination_port=49152,
    )

    response_two = make_response(
        timestamp + timedelta(seconds=3),
        destination_port=49153,
    )

    tracker = HTTPTransactionTracker()

    tracker.add_request(request_one)
    tracker.add_request(request_two)

    tracker.add_response(response_two)
    tracker.add_response(response_one)

    transactions = tracker.transactions()

    assert len(transactions) == 2

    assert transactions[0].request is request_two
    assert transactions[0].response is response_two

    assert transactions[1].request is request_one
    assert transactions[1].response is response_one