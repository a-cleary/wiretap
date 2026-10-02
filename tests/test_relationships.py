from datetime import datetime, timezone

from wiretap.capture.flow import Flow
from wiretap.capture.relationships import RelationshipTracker
from wiretap.models import (
    DNSAnswer,
    DNSQuery,
    DNSTransaction,
    Endpoint,
    EntityRef,
)


def test_relationship_tracker_adds_relationship():
    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    tracker = RelationshipTracker()

    tracker.add(
        source=EntityRef(
            type="host",
            value="10.10.10.42",
        ),
        relation="connects_to",
        target=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        timestamp=timestamp,
    )

    relationships = tracker.relationships()

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == EntityRef(
        type="host",
        value="10.10.10.42",
    )

    assert relationship.relation == "connects_to"

    assert relationship.target == EntityRef(
        type="host",
        value="10.10.10.20",
    )

    assert relationship.first_seen == timestamp
    assert relationship.last_seen == timestamp


def test_relationship_tracker_deduplicates_relationships():
    first_seen = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    second_seen = datetime(
        2026,
        1,
        1,
        0,
        0,
        5,
        tzinfo=timezone.utc,
    )

    tracker = RelationshipTracker()

    source = EntityRef(
        type="host",
        value="10.10.10.42",
    )

    target = EntityRef(
        type="host",
        value="10.10.10.20",
    )

    tracker.add(
        source=source,
        relation="connects_to",
        target=target,
        timestamp=first_seen,
    )

    tracker.add(
        source=source,
        relation="connects_to",
        target=target,
        timestamp=second_seen,
    )

    relationships = tracker.relationships()

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.first_seen == first_seen
    assert relationship.last_seen == second_seen


def test_relationship_tracker_adds_flow_relationship():
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

    tracker = RelationshipTracker()

    tracker.add_flow(flow)

    relationships = tracker.relationships()

    assert len(relationships) == 2

    connects_to = next(
        relationship
        for relationship in relationships
        if relationship.relation == "connects_to"
    )

    assert connects_to.source == EntityRef(
        type="host",
        value="10.10.10.42",
    )

    assert connects_to.relation == "connects_to"

    assert connects_to.target == EntityRef(
        type="host",
        value="10.10.10.20",
    )

    runs = next(
        relationship
        for relationship in relationships
        if relationship.relation == "runs"
    )

    assert runs.source == EntityRef(
        type="host",
        value="10.10.10.20",
    )

    assert runs.relation == "runs"

    assert runs.target == EntityRef(
        type="service",
        value="tcp/80",
    )


def test_relationship_tracker_adds_service_relationship():
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

    tracker = RelationshipTracker()

    tracker.add_flow(flow)

    relationships = tracker.relationships()

    service_relationship = next(
        relationship
        for relationship in relationships
        if relationship.relation == "runs"
    )

    assert service_relationship.source == EntityRef(
        type="host",
        value="10.10.10.20",
    )

    assert service_relationship.relation == "runs"

    assert service_relationship.target == EntityRef(
        type="service",
        value="tcp/80",
    )


def test_relationship_tracker_adds_dns_query_relationship():
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
        answers=[],
        response_code=0,
    )

    tracker = RelationshipTracker()

    tracker.add_dns_transaction(transaction)

    relationships = tracker.relationships()

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == EntityRef(
        type="host",
        value="10.10.10.42",
    )

    assert relationship.relation == "queried"

    assert relationship.target == EntityRef(
        type="hostname",
        value="fileserver.corp.local",
    )


def test_relationship_tracker_adds_dns_resolution_relationship():
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

    tracker = RelationshipTracker()

    tracker.add_dns_transaction(transaction)

    relationships = tracker.relationships()

    assert len(relationships) == 2

    resolution = next(
        relationship
        for relationship in relationships
        if relationship.relation == "resolves_to"
    )

    assert resolution.source == EntityRef(
        type="hostname",
        value="fileserver.corp.local",
    )

    assert resolution.target == EntityRef(
        type="host",
        value="10.10.10.20",
    )