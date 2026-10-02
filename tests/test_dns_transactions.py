from datetime import datetime, timezone

from wiretap.capture.dns_transactions import (
    DNSTransactionTracker,
)
from wiretap.models import (
    DNSAnswer,
    DNSQuery,
)


def make_query(
    transaction_id: int = 1234,
    source_ip: str = "10.10.10.42",
    destination_ip: str = "10.10.10.10",
) -> DNSQuery:
    return DNSQuery(
        timestamp=datetime(
            2026,
            9,
            30,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        source_ip=source_ip,
        destination_ip=destination_ip,
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=transaction_id,
    )


def make_answer() -> DNSAnswer:
    return DNSAnswer(
        name="fileserver.corp.local",
        record_type="A",
        value="10.10.10.20",
        ttl=300,
    )


def test_dns_query_and_response_are_correlated():
    tracker = DNSTransactionTracker()

    query = make_query()

    tracker.add_query(query)

    response_timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        1,
        tzinfo=timezone.utc,
    )

    tracker.add_response(
        source_ip="10.10.10.10",
        destination_ip="10.10.10.42",
        transaction_id=1234,
        answers=[make_answer()],
        response_code=0,
        timestamp=response_timestamp,
    )

    transactions = tracker.transactions()

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.query.query == "fileserver.corp.local"
    assert transaction.query.query_type == "A"
    assert transaction.query.transaction_id == 1234

    assert transaction.source_ip == "10.10.10.42"
    assert transaction.destination_ip == "10.10.10.10"

    assert transaction.response_code == 0

    assert len(transaction.answers) == 1
    assert transaction.answers[0].value == "10.10.10.20"

    assert transaction.timestamp == response_timestamp


def test_unmatched_query_remains_pending():
    tracker = DNSTransactionTracker()

    query = make_query()

    tracker.add_query(query)

    assert tracker.transactions() == []
    assert tracker.pending_queries() == [query]


def test_wrong_transaction_id_does_not_match():
    tracker = DNSTransactionTracker()

    query = make_query(transaction_id=1234)

    tracker.add_query(query)

    tracker.add_response(
        source_ip="10.10.10.10",
        destination_ip="10.10.10.42",
        transaction_id=5678,
        answers=[make_answer()],
        response_code=0,
        timestamp=query.timestamp,
    )

    assert tracker.transactions() == []
    assert tracker.pending_queries() == [query]


def test_wrong_server_does_not_match():
    tracker = DNSTransactionTracker()

    query = make_query(
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
    )

    tracker.add_query(query)

    tracker.add_response(
        source_ip="10.10.10.11",
        destination_ip="10.10.10.42",
        transaction_id=1234,
        answers=[make_answer()],
        response_code=0,
        timestamp=query.timestamp,
    )

    assert tracker.transactions() == []
    assert tracker.pending_queries() == [query]


def test_multiple_dns_transactions_are_kept_separate():
    tracker = DNSTransactionTracker()

    query_one = make_query(transaction_id=100)
    query_two = make_query(transaction_id=200)

    tracker.add_query(query_one)
    tracker.add_query(query_two)

    tracker.add_response(
        source_ip="10.10.10.10",
        destination_ip="10.10.10.42",
        transaction_id=200,
        answers=[make_answer()],
        response_code=0,
        timestamp=query_two.timestamp,
    )

    tracker.add_response(
        source_ip="10.10.10.10",
        destination_ip="10.10.10.42",
        transaction_id=100,
        answers=[make_answer()],
        response_code=0,
        timestamp=query_one.timestamp,
    )

    transactions = tracker.transactions()

    assert len(transactions) == 2
    assert transactions[0].query.transaction_id == 200
    assert transactions[1].query.transaction_id == 100

    assert tracker.pending_queries() == []