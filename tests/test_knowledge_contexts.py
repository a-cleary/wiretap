from datetime import datetime, timezone

from wiretap.models import (
    CertificateContext,
    EntityRef,
    HostnameContext,
    IdentityContext,
    KnowledgeModel,
    PathContext,
    ServiceContext,
    ShareContext,
    TLSCertificate,
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

    certificate = TLSCertificate(
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
    )

    knowledge.add_certificate(
        fingerprint_sha256="abc123",
        timestamp=timestamp(4),
        certificate=certificate,
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


def test_hostname_context_returns_context():
    knowledge = build_knowledge_model()

    context = knowledge.hostname_context(
        "fileserver.corp.local"
    )

    assert isinstance(
        context,
        HostnameContext,
    )


def test_hostname_context_contains_resolved_hosts():
    knowledge = build_knowledge_model()

    context = knowledge.hostname_context(
        "fileserver.corp.local"
    )

    assert context is not None

    assert {
        host.ip
        for host in context.resolved_hosts
    } == {
        "10.10.10.20",
    }


def test_hostname_context_contains_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.hostname_context(
        "fileserver.corp.local"
    )

    assert context is not None

    assert len(
        context.outgoing_relationships
    ) == 1

    relationship = (
        context.outgoing_relationships[0]
    )

    assert relationship.relation == "resolves_to"


def test_unknown_hostname_returns_none():
    knowledge = build_knowledge_model()

    assert (
        knowledge.hostname_context(
            "unknown.corp.local"
        )
        is None
    )


def test_service_context_returns_context():
    knowledge = build_knowledge_model()

    context = knowledge.service_context(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
    )

    assert isinstance(
        context,
        ServiceContext,
    )


def test_service_context_contains_host():
    knowledge = build_knowledge_model()

    context = knowledge.service_context(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
    )

    assert context is not None
    assert context.host is not None
    assert context.host.ip == "10.10.10.20"


def test_service_context_contains_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.service_context(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
    )

    assert context is not None

    assert len(
        context.outgoing_relationships
    ) == 0

    assert len(
        context.incoming_relationships
    ) == 1

    relationship = (
        context.incoming_relationships[0]
    )

    assert relationship.relation == "runs"


def test_unknown_service_returns_none():
    knowledge = build_knowledge_model()

    assert (
        knowledge.service_context(
            host_ip="10.10.10.20",
            port=443,
            protocol="tcp",
        )
        is None
    )


def test_identity_context_returns_context():
    knowledge = build_knowledge_model()

    context = knowledge.identity_context(
        r"CORP\alice"
    )

    assert isinstance(
        context,
        IdentityContext,
    )


def test_identity_context_contains_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.identity_context(
        r"CORP\alice"
    )

    assert context is not None

    assert len(
        context.incoming_relationships
    ) == 1

    relationship = (
        context.incoming_relationships[0]
    )

    assert relationship.source == EntityRef(
        type="host",
        value="10.10.10.20",
    )

    assert relationship.relation == (
        "authenticated_as"
    )


def test_unknown_identity_returns_none():
    knowledge = build_knowledge_model()

    assert (
        knowledge.identity_context(
            r"CORP\bob"
        )
        is None
    )


def test_share_context_returns_context():
    knowledge = build_knowledge_model()

    context = knowledge.share_context(
        r"\\10.10.10.20\ADMIN$"
    )

    assert isinstance(
        context,
        ShareContext,
    )


def test_share_context_contains_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.share_context(
        r"\\10.10.10.20\ADMIN$"
    )

    assert context is not None

    assert len(
        context.incoming_relationships
    ) == 1

    relationship = (
        context.incoming_relationships[0]
    )

    assert relationship.source == EntityRef(
        type="host",
        value="10.10.10.10",
    )

    assert relationship.relation == (
        "accessed_share"
    )


def test_unknown_share_returns_none():
    knowledge = build_knowledge_model()

    assert (
        knowledge.share_context(
            r"\\10.10.10.20\C$"
        )
        is None
    )


def test_path_context_returns_context():
    knowledge = build_knowledge_model()

    context = knowledge.path_context(
        r"\Temp\payload.exe"
    )

    assert isinstance(
        context,
        PathContext,
    )


def test_path_context_contains_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.path_context(
        r"\Temp\payload.exe"
    )

    assert context is not None

    assert len(
        context.incoming_relationships
    ) == 1

    relationship = (
        context.incoming_relationships[0]
    )

    assert relationship.source == EntityRef(
        type="host",
        value="10.10.10.10",
    )

    assert relationship.relation == "writes_to"


def test_unknown_path_returns_none():
    knowledge = build_knowledge_model()

    assert (
        knowledge.path_context(
            r"\Temp\missing.exe"
        )
        is None
    )


def test_certificate_context_returns_context():
    knowledge = build_knowledge_model()

    context = knowledge.certificate_context(
        "abc123"
    )

    assert isinstance(
        context,
        CertificateContext,
    )


def test_certificate_context_contains_certificate():
    knowledge = build_knowledge_model()

    context = knowledge.certificate_context(
        "abc123"
    )

    assert context is not None

    assert (
        context.certificate.fingerprint_sha256
        == "abc123"
    )

    assert (
        context.certificate.subject
        == "CN=fileserver.corp.local"
    )


def test_certificate_context_contains_relationships():
    knowledge = build_knowledge_model()

    context = knowledge.certificate_context(
        "abc123"
    )

    assert context is not None

    assert len(
        context.incoming_relationships
    ) == 1

    relationship = (
        context.incoming_relationships[0]
    )

    assert relationship.source == EntityRef(
        type="host",
        value="10.10.10.20",
    )

    assert relationship.relation == (
        "presented_certificate"
    )


def test_unknown_certificate_returns_none():
    knowledge = build_knowledge_model()

    assert (
        knowledge.certificate_context(
            "does-not-exist"
        )
        is None
    )