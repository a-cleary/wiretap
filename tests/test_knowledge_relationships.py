from datetime import datetime, timezone

from wiretap.capture.processor import CaptureProcessor
from wiretap.models import (
    DNSAnswer,
    DNSQuery,
    DNSTransaction,
    EntityRef,
    SMBFileOperation,
    SMBSessionSetup,
    SMBTreeConnect,
    TLSClientHello,
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


def test_flow_relationship_is_stored_in_knowledge_model():
    processor = CaptureProcessor()

    from wiretap.capture.flow import Flow
    from wiretap.models import Endpoint

    flow = Flow(
        endpoint_a=Endpoint(
            ip="10.10.10.10",
            port=50000,
        ),
        endpoint_b=Endpoint(
            ip="10.10.10.20",
            port=445,
        ),
        protocol="tcp",
        first_seen=timestamp(1),
        last_seen=timestamp(2),
        initiator=Endpoint(
            ip="10.10.10.10",
            port=50000,
        ),
        responder=Endpoint(
            ip="10.10.10.20",
            port=445,
        ),
    )

    processor.entity_tracker.add_flow(flow)
    processor.relationship_tracker.add_flow(flow)

    relationships = processor.knowledge.relationships()

    assert len(relationships) == 2

    assert processor.knowledge.entity(
        "host:10.10.10.10"
    ) is not None

    assert processor.knowledge.entity(
        "host:10.10.10.20"
    ) is not None

    assert processor.knowledge.entity(
        "service:tcp/445"
    ) is not None

    connects_to = processor.knowledge.relationship(
        "host:10.10.10.10:"
        "connects_to:"
        "host:10.10.10.20"
    )

    assert connects_to is not None

    runs = processor.knowledge.relationship(
        "host:10.10.10.20:"
        "runs:"
        "service:tcp/445"
    )

    assert runs is not None


def test_dns_relationships_are_stored_in_knowledge_model():
    processor = CaptureProcessor()

    query = DNSQuery(
        timestamp=timestamp(1),
        source_ip="10.10.10.10",
        destination_ip="10.10.10.53",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    transaction = DNSTransaction(
        timestamp=timestamp(2),
        source_ip="10.10.10.53",
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

    processor.entity_tracker.add_dns_transaction(
        transaction
    )
    processor.relationship_tracker.add_dns_transaction(
        transaction
    )

    assert processor.knowledge.entity(
        "host:10.10.10.10"
    ) is not None

    assert processor.knowledge.entity(
        "hostname:fileserver.corp.local"
    ) is not None

    assert processor.knowledge.entity(
        "host:10.10.10.20"
    ) is not None

    queried = processor.knowledge.relationship(
        "host:10.10.10.10:"
        "queried:"
        "hostname:fileserver.corp.local"
    )

    assert queried is not None

    resolves_to = processor.knowledge.relationship(
        "hostname:fileserver.corp.local:"
        "resolves_to:"
        "host:10.10.10.20"
    )

    assert resolves_to is not None


def test_tls_relationship_is_stored_in_knowledge_model():
    processor = CaptureProcessor()

    hello = TLSClientHello(
        timestamp=timestamp(1),
        source_ip="10.10.10.10",
        source_port=50000,
        destination_ip="10.10.10.20",
        destination_port=443,
        version="TLS 1.3",
        server_name="api.example.com",
        alpn_protocols=["h2"],
        cipher_suites=["TLS_AES_128_GCM_SHA256"],
    )

    from wiretap.models import TLSTransaction

    transaction = TLSTransaction(
        client_hello=hello,
    )

    processor.entity_tracker.add_tls_transaction(
        transaction
    )
    processor.relationship_tracker.add_tls_transaction(
        transaction
    )

    assert processor.knowledge.entity(
        "hostname:api.example.com"
    ) is not None

    accessed = processor.knowledge.relationship(
        "host:10.10.10.10:"
        "accessed:"
        "hostname:api.example.com"
    )

    assert accessed is not None


def test_smb_session_setup_relationship_is_stored():
    processor = CaptureProcessor()

    observation = SMBSessionSetup(
        timestamp=timestamp(1),
        source_ip="10.10.10.10",
        source_port=50000,
        destination_ip="10.10.10.20",
        destination_port=445,
        version="SMB3",
        command="SESSION_SETUP",
        message_type="request",
        session_id=123,
        username="alice",
        domain="CORP",
        workstation="WORKSTATION01",
    )

    processor.entity_tracker.add_smb_session_setup(
        observation
    )
    processor.relationship_tracker.add_smb_session_setup(
        observation
    )

    identity = EntityRef(
        type="identity",
        value=r"CORP\alice",
    )

    assert processor.knowledge.entity(
        identity.id
    ) == identity

    relationship = processor.knowledge.relationship(
        "host:10.10.10.10:"
        "authenticated_as:"
        r"identity:CORP\alice"
    )

    assert relationship is not None


def test_smb_tree_connect_relationship_is_stored():
    processor = CaptureProcessor()

    observation = SMBTreeConnect(
        timestamp=timestamp(1),
        source_ip="10.10.10.10",
        source_port=50000,
        destination_ip="10.10.10.20",
        destination_port=445,
        version="SMB3",
        command="TREE_CONNECT",
        message_type="request",
        session_id=123,
        tree_id=456,
        share=r"\\10.10.10.20\ADMIN$",
    )

    processor.entity_tracker.add_smb_tree_connect(
        observation
    )
    processor.relationship_tracker.add_smb_tree_connect(
        observation
    )

    share = EntityRef(
        type="share",
        value=r"\\10.10.10.20\ADMIN$",
    )

    assert processor.knowledge.entity(
        share.id
    ) == share

    relationship = processor.knowledge.relationship(
        "host:10.10.10.10:"
        "accessed_share:"
        r"share:\\10.10.10.20\ADMIN$"
    )

    assert relationship is not None


def test_smb_file_relationship_is_stored():
    processor = CaptureProcessor()

    observation = SMBFileOperation(
        timestamp=timestamp(1),
        source_ip="10.10.10.10",
        source_port=50000,
        destination_ip="10.10.10.20",
        destination_port=445,
        version="SMB3",
        command="CREATE",
        message_type="request",
        session_id=123,
        tree_id=456,
        operation="WRITE",
        path=r"\Temp\payload.exe",
    )

    processor.entity_tracker.add_smb_file_operation(
        observation
    )
    processor.relationship_tracker.add_smb_file_operation(
        observation
    )

    path = EntityRef(
        type="path",
        value=r"\Temp\payload.exe",
    )

    assert processor.knowledge.entity(
        path.id
    ) == path

    relationship = processor.knowledge.relationship(
        "host:10.10.10.10:"
        "writes_to:"
        r"path:\Temp\payload.exe"
    )

    assert relationship is not None