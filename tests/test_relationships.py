from datetime import datetime, timezone

from wiretap.capture.relationships import RelationshipTracker


def make_timestamp(second: int) -> datetime:
    return datetime(
        2026,
        1,
        1,
        0,
        0,
        second,
        tzinfo=timezone.utc,
    )


def test_relationship_tracker_adds_relationship():
    tracker = RelationshipTracker()

    timestamp = make_timestamp(1)

    tracker.add(
        source="10.10.10.42",
        relation="queried",
        target="fileserver.corp.local",
        timestamp=timestamp,
    )

    relationships = tracker.relationships()

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == "10.10.10.42"
    assert relationship.relation == "queried"
    assert relationship.target == "fileserver.corp.local"
    assert relationship.first_seen == timestamp
    assert relationship.last_seen == timestamp


def test_relationship_tracker_deduplicates_relationships():
    tracker = RelationshipTracker()

    first = make_timestamp(1)
    second = make_timestamp(5)

    tracker.add(
        source="10.10.10.42",
        relation="connects_to",
        target="10.10.10.20",
        timestamp=first,
    )

    tracker.add(
        source="10.10.10.42",
        relation="connects_to",
        target="10.10.10.20",
        timestamp=second,
    )

    relationships = tracker.relationships()

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.first_seen == first
    assert relationship.last_seen == second


def test_relationship_tracker_keeps_distinct_relationships():
    tracker = RelationshipTracker()

    timestamp = make_timestamp(1)

    tracker.add(
        source="10.10.10.42",
        relation="connects_to",
        target="10.10.10.20",
        timestamp=timestamp,
    )

    tracker.add(
        source="10.10.10.42",
        relation="connects_to",
        target="10.10.10.30",
        timestamp=timestamp,
    )

    tracker.add(
        source="10.10.10.42",
        relation="queried",
        target="fileserver.corp.local",
        timestamp=timestamp,
    )

    relationships = tracker.relationships()

    assert len(relationships) == 3


def test_relationship_tracker_adds_flow_connection():
    from datetime import datetime, timezone

    from wiretap.capture.flow import Flow
    from wiretap.models import Endpoint

    tracker = RelationshipTracker()

    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    flow = Flow(
        endpoint_a=Endpoint(
            ip="10.10.10.20",
            port=80,
        ),
        endpoint_b=Endpoint(
            ip="10.10.10.42",
            port=49152,
        ),
        protocol="tcp",
        first_seen=timestamp,
        last_seen=timestamp,
        initiator=Endpoint(
            ip="10.10.10.42",
            port=49152,
        ),
        responder=Endpoint(
            ip="10.10.10.20",
            port=80,
        ),
    )

    tracker.add_flow(flow)

    relationships = tracker.relationships()

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == "10.10.10.42"
    assert relationship.relation == "connects_to"
    assert relationship.target == "10.10.10.20"
    assert relationship.first_seen == timestamp
    assert relationship.last_seen == timestamp


def test_relationship_tracker_adds_dns_transaction():
    from datetime import datetime, timezone

    from wiretap.models import (
        DNSAnswer,
        DNSQuery,
        DNSTransaction,
    )

    tracker = RelationshipTracker()

    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    query = DNSQuery(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    transaction = DNSTransaction(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query=query,
        answers=[
            DNSAnswer(
                name="fileserver.corp.local",
                record_type="A",
                value="10.10.10.20",
                ttl=300,
            )
        ],
        response_code=0,
    )

    tracker.add_dns_transaction(transaction)

    relationships = tracker.relationships()

    assert {
        (
            relationship.source,
            relationship.relation,
            relationship.target,
        )
        for relationship in relationships
    } == {
        (
            "10.10.10.42",
            "queried",
            "fileserver.corp.local",
        ),
        (
            "fileserver.corp.local",
            "resolves_to",
            "10.10.10.20",
        ),
    }