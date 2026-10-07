from datetime import datetime, timezone

from wiretap.models import (
    EntityRef,
    HostContext,
    KnowledgeModel,
)


def timestamp(
    second: int,
) -> datetime:
    return datetime(
        2026,
        1,
        1,
        0,
        0,
        second,
        tzinfo=timezone.utc,
    )


def build_knowledge_model() -> KnowledgeModel:
    knowledge = KnowledgeModel()

    knowledge.add_host(
        ip="10.10.10.10",
        first_seen=timestamp(1),
        last_seen=timestamp(5),
    )

    knowledge.add_host(
        ip="10.10.10.20",
        first_seen=timestamp(2),
        last_seen=timestamp(6),
    )

    knowledge.add_host(
        ip="10.10.10.30",
        first_seen=timestamp(3),
        last_seen=timestamp(7),
    )

    knowledge.add_hostname(
        name="fileserver.corp.local",
        first_seen=timestamp(2),
        last_seen=timestamp(6),
    )

    knowledge.add_hostname(
        name="files.corp.local",
        first_seen=timestamp(3),
        last_seen=timestamp(5),
    )

    knowledge.add_service(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
        first_seen=timestamp(2),
        last_seen=timestamp(6),
    )

    knowledge.add_service(
        host_ip="10.10.10.20",
        port=443,
        protocol="tcp",
        first_seen=timestamp(3),
        last_seen=timestamp(6),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.10",
        ),
        relation="connects_to",
        target=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        timestamp=timestamp(2),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        relation="connects_to",
        target=EntityRef(
            type="host",
            value="10.10.10.10",
        ),
        timestamp=timestamp(3),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="hostname",
            value="fileserver.corp.local",
        ),
        relation="resolves_to",
        target=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        timestamp=timestamp(4),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="hostname",
            value="files.corp.local",
        ),
        relation="resolves_to",
        target=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        timestamp=timestamp(5),
    )

    return knowledge


def test_host_context_returns_context_for_known_host():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert isinstance(
        context,
        HostContext,
    )


def test_host_context_returns_none_for_unknown_host():
    knowledge = build_knowledge_model()

    assert (
        knowledge.host_context(
            "10.10.10.99"
        )
        is None
    )


def test_host_context_contains_host():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None
    assert context.host.ip == "10.10.10.20"
    assert context.host.first_seen == timestamp(2)
    assert context.host.last_seen == timestamp(6)


def test_host_context_contains_hostnames():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None

    assert {
        hostname.name
        for hostname in context.hostnames
    } == {
        "fileserver.corp.local",
        "files.corp.local",
    }


def test_host_context_contains_services():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None

    assert {
        (service.protocol, service.port)
        for service in context.services
    } == {
        ("tcp", 445),
        ("tcp", 443),
    }


def test_host_context_contains_related_hosts():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None

    assert {
        host.ip
        for host in context.related_hosts
    } == {
        "10.10.10.10",
    }


def test_host_context_contains_outgoing_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None

    assert len(
        context.outgoing_relationships
    ) == 1

    relationship = (
        context.outgoing_relationships[0]
    )

    assert relationship.source == EntityRef(
        type="host",
        value="10.10.10.20",
    )

    assert relationship.relation == "connects_to"

    assert relationship.target == EntityRef(
        type="host",
        value="10.10.10.10",
    )


def test_host_context_contains_incoming_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None

    assert len(
        context.incoming_relationships
    ) == 3

    incoming = {
        (
            relationship.source.id,
            relationship.relation,
            relationship.target.id,
        )
        for relationship
        in context.incoming_relationships
    }

    assert incoming == {
        (
            "host:10.10.10.10",
            "connects_to",
            "host:10.10.10.20",
        ),
        (
            "hostname:fileserver.corp.local",
            "resolves_to",
            "host:10.10.10.20",
        ),
        (
            "hostname:files.corp.local",
            "resolves_to",
            "host:10.10.10.20",
        ),
    }


def test_host_context_preserves_relationship_time_windows():
    knowledge = build_knowledge_model()

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.10",
        ),
        relation="connects_to",
        target=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        timestamp=timestamp(8),
    )

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None

    relationship = next(
        relationship
        for relationship
        in context.incoming_relationships
        if relationship.relation
        == "connects_to"
    )

    assert relationship.first_seen == timestamp(2)
    assert relationship.last_seen == timestamp(8)


def test_host_context_is_consistent_with_individual_queries():
    knowledge = build_knowledge_model()

    context = knowledge.host_context(
        "10.10.10.20"
    )

    assert context is not None

    assert context.host == knowledge.host(
        "10.10.10.20"
    )

    assert context.hostnames == (
        knowledge.hostnames_for_host(
            "10.10.10.20"
        )
    )

    assert context.services == (
        knowledge.services_for_host(
            "10.10.10.20"
        )
    )

    assert context.related_hosts == (
        knowledge.related_hosts(
            "10.10.10.20"
        )
    )

    assert context.outgoing_relationships == (
        knowledge.relationships_from(
            EntityRef(
                type="host",
                value="10.10.10.20",
            )
        )
    )

    assert context.incoming_relationships == (
        knowledge.relationships_to(
            EntityRef(
                type="host",
                value="10.10.10.20",
            )
        )
    )