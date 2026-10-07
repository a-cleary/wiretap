from datetime import datetime, timezone

from wiretap.models import (
    EntityRef,
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


def test_add_host_registers_entity():
    knowledge = KnowledgeModel()

    host = knowledge.add_host(
        ip="10.10.10.10",
        first_seen=timestamp(1),
        last_seen=timestamp(2),
    )

    assert host.ip == "10.10.10.10"
    assert host.first_seen == timestamp(1)
    assert host.last_seen == timestamp(2)

    assert knowledge.entity(
        "host:10.10.10.10"
    ) == EntityRef(
        type="host",
        value="10.10.10.10",
    )


def test_add_host_merges_observation_window():
    knowledge = KnowledgeModel()

    knowledge.add_host(
        ip="10.10.10.10",
        first_seen=timestamp(5),
        last_seen=timestamp(10),
    )

    host = knowledge.add_host(
        ip="10.10.10.10",
        first_seen=timestamp(1),
        last_seen=timestamp(20),
    )

    assert host.first_seen == timestamp(1)
    assert host.last_seen == timestamp(20)

    assert len(knowledge.hosts()) == 1


def test_add_hostname_registers_entity():
    knowledge = KnowledgeModel()

    hostname = knowledge.add_hostname(
        name="server.example.com",
        first_seen=timestamp(1),
        last_seen=timestamp(2),
    )

    assert hostname.name == "server.example.com"

    assert knowledge.entity(
        "hostname:server.example.com"
    ) == EntityRef(
        type="hostname",
        value="server.example.com",
    )


def test_add_hostname_merges_observation_window():
    knowledge = KnowledgeModel()

    knowledge.add_hostname(
        name="server.example.com",
        first_seen=timestamp(5),
        last_seen=timestamp(10),
    )

    hostname = knowledge.add_hostname(
        name="server.example.com",
        first_seen=timestamp(1),
        last_seen=timestamp(20),
    )

    assert hostname.first_seen == timestamp(1)
    assert hostname.last_seen == timestamp(20)

    assert len(knowledge.hostnames()) == 1


def test_add_service_registers_entity():
    knowledge = KnowledgeModel()

    service = knowledge.add_service(
        host_ip="10.10.10.10",
        port=443,
        protocol="tcp",
        first_seen=timestamp(1),
        last_seen=timestamp(2),
    )

    assert service.host_ip == "10.10.10.10"
    assert service.port == 443
    assert service.protocol == "tcp"

    assert knowledge.entity(
        "service:tcp/443"
    ) == EntityRef(
        type="service",
        value="tcp/443",
    )


def test_add_service_merges_observation_window():
    knowledge = KnowledgeModel()

    knowledge.add_service(
        host_ip="10.10.10.10",
        port=443,
        protocol="tcp",
        first_seen=timestamp(5),
        last_seen=timestamp(10),
    )

    service = knowledge.add_service(
        host_ip="10.10.10.10",
        port=443,
        protocol="tcp",
        first_seen=timestamp(1),
        last_seen=timestamp(20),
    )

    assert service.first_seen == timestamp(1)
    assert service.last_seen == timestamp(20)

    assert len(knowledge.services()) == 1


def test_add_certificate_registers_entity():
    knowledge = KnowledgeModel()

    certificate = knowledge.add_certificate(
        fingerprint_sha256="abc123",
        timestamp=timestamp(5),
    )

    assert certificate.fingerprint_sha256 == "abc123"

    assert knowledge.entity(
        "certificate:abc123"
    ) == EntityRef(
        type="certificate",
        value="abc123",
    )


def test_add_generic_entity_registers_entity():
    knowledge = KnowledgeModel()

    entity = knowledge.add_entity(
        EntityRef(
            type="identity",
            value=r"CORP\alice",
        )
    )

    assert entity in knowledge.entities()

    assert knowledge.entity(
        r"identity:CORP\alice"
    ) == entity


def test_clear_removes_entities_and_rich_records():
    knowledge = KnowledgeModel()

    knowledge.add_host(
        ip="10.10.10.10",
        first_seen=timestamp(1),
        last_seen=timestamp(2),
    )

    knowledge.add_hostname(
        name="server.example.com",
        first_seen=timestamp(1),
        last_seen=timestamp(2),
    )

    knowledge.add_service(
        host_ip="10.10.10.10",
        port=443,
        protocol="tcp",
        first_seen=timestamp(1),
        last_seen=timestamp(2),
    )

    knowledge.add_entity(
        EntityRef(
            type="identity",
            value=r"CORP\alice",
        )
    )

    knowledge.clear()

    assert knowledge.entities() == []
    assert knowledge.relationships() == []
    assert knowledge.hosts() == []
    assert knowledge.hostnames() == []
    assert knowledge.services() == []
    assert knowledge.certificates() == []


def test_add_identity_without_domain():
    knowledge = KnowledgeModel()

    identity = knowledge.add_identity(
        username="alice",
    )

    assert identity == EntityRef(
        type="identity",
        value="alice",
    )

    assert knowledge.entity(
        "identity:alice"
    ) == identity


def test_add_identity_with_domain():
    knowledge = KnowledgeModel()

    identity = knowledge.add_identity(
        username="alice",
        domain="CORP",
    )

    assert identity == EntityRef(
        type="identity",
        value=r"CORP\alice",
    )

    assert knowledge.entity(
        r"identity:CORP\alice"
    ) == identity


def test_add_share_registers_entity():
    knowledge = KnowledgeModel()

    share = knowledge.add_share(
        r"\\10.10.10.30\ADMIN$"
    )

    assert share == EntityRef(
        type="share",
        value=r"\\10.10.10.30\ADMIN$",
    )

    assert knowledge.entity(
        r"share:\\10.10.10.30\ADMIN$"
    ) == share


def test_add_path_registers_entity():
    knowledge = KnowledgeModel()

    path = knowledge.add_path(
        r"\Temp\payload.exe"
    )

    assert path == EntityRef(
        type="path",
        value=r"\Temp\payload.exe",
    )

    assert knowledge.entity(
        r"path:\Temp\payload.exe"
    ) == path


def test_generic_entity_helpers_do_not_duplicate_entities():
    knowledge = KnowledgeModel()

    first = knowledge.add_identity(
        username="alice",
        domain="CORP",
    )

    second = knowledge.add_identity(
        username="alice",
        domain="CORP",
    )

    assert first is second
    assert len(knowledge.entities()) == 1