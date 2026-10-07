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
        name="dc01.corp.local",
        first_seen=timestamp(3),
        last_seen=timestamp(7),
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

    knowledge.add_service(
        host_ip="10.10.10.30",
        port=53,
        protocol="udp",
        first_seen=timestamp(4),
        last_seen=timestamp(7),
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
            value="10.10.10.10",
        ),
        relation="connects_to",
        target=EntityRef(
            type="host",
            value="10.10.10.30",
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
            value="dc01.corp.local",
        ),
        relation="resolves_to",
        target=EntityRef(
            type="host",
            value="10.10.10.30",
        ),
        timestamp=timestamp(5),
    )

    return knowledge


def test_host_returns_host_record():
    knowledge = build_knowledge_model()

    host = knowledge.host(
        "10.10.10.20"
    )

    assert host is not None
    assert host.ip == "10.10.10.20"


def test_host_returns_none_for_unknown_host():
    knowledge = build_knowledge_model()

    assert (
        knowledge.host("10.10.10.99")
        is None
    )


def test_hostname_returns_hostname_record():
    knowledge = build_knowledge_model()

    hostname = knowledge.hostname(
        "fileserver.corp.local"
    )

    assert hostname is not None
    assert (
        hostname.name
        == "fileserver.corp.local"
    )


def test_hostname_returns_none_for_unknown_hostname():
    knowledge = build_knowledge_model()

    assert (
        knowledge.hostname(
            "unknown.corp.local"
        )
        is None
    )


def test_service_returns_service_for_host():
    knowledge = build_knowledge_model()

    service = knowledge.service(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
    )

    assert service is not None
    assert service.host_ip == "10.10.10.20"
    assert service.port == 445
    assert service.protocol == "tcp"


def test_service_distinguishes_hosts():
    knowledge = build_knowledge_model()

    assert (
        knowledge.service(
            host_ip="10.10.10.20",
            port=53,
            protocol="udp",
        )
        is None
    )

    assert (
        knowledge.service(
            host_ip="10.10.10.30",
            port=53,
            protocol="udp",
        )
        is not None
    )


def test_services_for_host_returns_all_services():
    knowledge = build_knowledge_model()

    services = knowledge.services_for_host(
        "10.10.10.20"
    )

    assert len(services) == 2

    assert {
        (service.protocol, service.port)
        for service in services
    } == {
        ("tcp", 445),
        ("tcp", 443),
    }


def test_services_for_unknown_host_returns_empty_list():
    knowledge = build_knowledge_model()

    assert (
        knowledge.services_for_host(
            "10.10.10.99"
        )
        == []
    )


def test_related_hosts_returns_outgoing_hosts():
    knowledge = build_knowledge_model()

    hosts = knowledge.related_hosts(
        "10.10.10.10"
    )

    assert {
        host.ip
        for host in hosts
    } == {
        "10.10.10.20",
        "10.10.10.30",
    }


def test_related_hosts_can_filter_relationship():
    knowledge = build_knowledge_model()

    hosts = knowledge.related_hosts(
        "10.10.10.10",
        relation="connects_to",
    )

    assert {
        host.ip
        for host in hosts
    } == {
        "10.10.10.20",
        "10.10.10.30",
    }


def test_related_hosts_ignores_non_host_targets():
    knowledge = build_knowledge_model()

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.10",
        ),
        relation="accessed",
        target=EntityRef(
            type="hostname",
            value="fileserver.corp.local",
        ),
        timestamp=timestamp(6),
    )

    hosts = knowledge.related_hosts(
        "10.10.10.10"
    )

    assert {
        host.ip
        for host in hosts
    } == {
        "10.10.10.20",
        "10.10.10.30",
    }


def test_hostnames_for_host_returns_resolving_hostnames():
    knowledge = build_knowledge_model()

    hostnames = knowledge.hostnames_for_host(
        "10.10.10.20"
    )

    assert {
        hostname.name
        for hostname in hostnames
    } == {
        "fileserver.corp.local",
    }


def test_hostnames_for_unknown_host_returns_empty_list():
    knowledge = build_knowledge_model()

    assert (
        knowledge.hostnames_for_host(
            "10.10.10.99"
        )
        == []
    )


def test_hostnames_for_host_only_returns_hostname_entities():
    knowledge = build_knowledge_model()

    knowledge.add_relationship(
        source=EntityRef(
            type="service",
            value="tcp/445",
        ),
        relation="runs_on",
        target=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        timestamp=timestamp(6),
    )

    hostnames = knowledge.hostnames_for_host(
        "10.10.10.20"
    )

    assert {
        hostname.name
        for hostname in hostnames
    } == {
        "fileserver.corp.local",
    }