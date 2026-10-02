from datetime import datetime, timezone

from wiretap.capture.smb_transactions import (
    SMBTransactionTracker,
)
from wiretap.models import SMBObservation


def observation(
    *,
    source_ip="10.10.10.42",
    destination_ip="10.10.10.30",
    source_port=49153,
    destination_port=445,
    message_type="request",
    message_id=1,
):
    return SMBObservation(
        timestamp=datetime.now(timezone.utc),
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        version="SMB3",
        command="CREATE",
        message_type=message_type,
        message_id=message_id,
    )


def test_smb_request_response_are_correlated():
    tracker = SMBTransactionTracker()

    request = observation(
        message_type="request",
        message_id=42,
    )

    response = observation(
        source_ip="10.10.10.30",
        destination_ip="10.10.10.42",
        source_port=445,
        destination_port=49153,
        message_type="response",
        message_id=42,
    )

    tracker.add(request)
    tracker.add(response)

    transactions = tracker.transactions()

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.request is request
    assert transaction.response is response


def test_unmatched_response_is_preserved():
    tracker = SMBTransactionTracker()

    response = observation(
        source_ip="10.10.10.30",
        destination_ip="10.10.10.42",
        source_port=445,
        destination_port=49153,
        message_type="response",
        message_id=999,
    )

    tracker.add(response)

    transactions = tracker.transactions()

    assert len(transactions) == 1

    assert transactions[0].request is None
    assert transactions[0].response is response


def test_pending_requests_are_available():
    tracker = SMBTransactionTracker()

    request = observation(
        message_type="request",
        message_id=100,
    )

    tracker.add(request)

    assert tracker.pending() == [request]