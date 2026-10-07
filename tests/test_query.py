from datetime import datetime, timezone

from wiretap.models import (
    EntityRef,
    KnowledgeModel,
    TLSCertificate,
)
from wiretap.query import QueryEngine


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
        last_seen=timestamp(8),
    )

    knowledge.add_host(
        ip="10.10.10.20",
        first_seen=timestamp(2),
        last_seen=timestamp(7),
    )

    knowledge.add_hostname(
        name="fileserver.corp.local",
        first_seen=timestamp(2),
        last_seen=timestamp(7),
    )

    knowledge.add_service(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
        first_seen=timestamp(2),
        last_seen=timestamp(7),
    )

    knowledge.add_identity(
        username="alice",
        domain="CORP",
    )

    knowledge.add_share(
        share=r"\\10.10.10.20\ADMIN$"
    )

    knowledge.add_path(
        path=r"\Temp\payload.exe"
    )

    knowledge.add_certificate(
        fingerprint_sha256="abc123",
        timestamp=timestamp(4),
        certificate=TLSCertificate(
            timestamp=timestamp(4),
            source_ip="10.10.10.20",
            source_port=443,
            destination_ip="10.10.10.10",
            destination_port=50000,
            fingerprint_sha256="abc123",
            subject="CN=fileserver.corp.local",
            issuer="CN=Corp CA",
            serial_number="1234",
            not_before=timestamp(1),
            not_after=timestamp(50),
            subject_alt_names=[
                "fileserver.corp.local",
            ],
        ),
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
        timestamp=timestamp(3),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.10",
        ),
        relation="runs",
        target=EntityRef(
            type="service",
            value="tcp/445",
        ),
        timestamp=timestamp(4),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        relation="authenticated_as",
        target=EntityRef(
            type="identity",
            value=r"CORP\alice",
        ),
        timestamp=timestamp(5),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.10",
        ),
        relation="accessed_share",
        target=EntityRef(
            type="share",
            value=r"\\10.10.10.20\ADMIN$",
        ),
        timestamp=timestamp(6),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.10",
        ),
        relation="writes_to",
        target=EntityRef(
            type="path",
            value=r"\Temp\payload.exe",
        ),
        timestamp=timestamp(7),
    )

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        relation="presented_certificate",
        target=EntityRef(
            type="certificate",
            value="abc123",
        ),
        timestamp=timestamp(4),
    )

    return knowledge


def test_query_engine_uses_knowledge_model():
    knowledge = build_knowledge_model()

    query = QueryEngine(
        knowledge=knowledge
    )

    context = query.host(
        "10.10.10.20"
    )

    assert context is not None
    assert context.host.ip == "10.10.10.20"


def test_query_host():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    context = query.host(
        "10.10.10.20"
    )

    assert context is not None
    assert context.host.ip == "10.10.10.20"


def test_query_unknown_host():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    assert (
        query.host(
            "10.10.10.99"
        )
        is None
    )


def test_query_hostname():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    context = query.hostname(
        "fileserver.corp.local"
    )

    assert context is not None
    assert context.hostname.name == (
        "fileserver.corp.local"
    )


def test_query_unknown_hostname():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    assert (
        query.hostname(
            "missing.corp.local"
        )
        is None
    )


def test_query_service():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    context = query.service(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
    )

    assert context is not None
    assert context.service.host_ip == (
        "10.10.10.20"
    )
    assert context.service.port == 445
    assert context.service.protocol == "tcp"


def test_query_unknown_service():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    assert (
        query.service(
            host_ip="10.10.10.20",
            port=443,
            protocol="tcp",
        )
        is None
    )


def test_query_identity():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    context = query.identity(
        r"CORP\alice"
    )

    assert context is not None
    assert context.identity == (
        r"CORP\alice"
    )


def test_query_unknown_identity():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    assert (
        query.identity(
            r"CORP\bob"
        )
        is None
    )


def test_query_share():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    context = query.share(
        r"\\10.10.10.20\ADMIN$"
    )

    assert context is not None
    assert context.share == (
        r"\\10.10.10.20\ADMIN$"
    )


def test_query_unknown_share():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    assert (
        query.share(
            r"\\10.10.10.20\C$"
        )
        is None
    )


def test_query_path():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    context = query.path(
        r"\Temp\payload.exe"
    )

    assert context is not None
    assert context.path == (
        r"\Temp\payload.exe"
    )


def test_query_unknown_path():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    assert (
        query.path(
            r"\Temp\missing.exe"
        )
        is None
    )


def test_query_certificate():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    context = query.certificate(
        "abc123"
    )

    assert context is not None
    assert (
        context.certificate.fingerprint_sha256
        == "abc123"
    )


def test_query_unknown_certificate():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    assert (
        query.certificate(
            "does-not-exist"
        )
        is None
    )