from datetime import datetime, timezone

import pytest

from wiretap.capture.flow import Flow
from wiretap.models import (
    Connection,
    DNSAnswer,
    DNSQuery,
    DNSTransaction,
    Endpoint,
    EntityRef,
    Hostname,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    Relationship,
    Service,
    TLSClientHello,
    TLSServerHello,
    TLSTransaction,
    TLSCertificate,
    SMBFileOperation,
    SMBSessionSetup,
    SMBTreeConnect,
    SMBTransaction,
)
from wiretap.output.timeline import (
    TimelineRecord,
    connection_to_timeline,
    dns_to_timeline,
    dns_transaction_to_timeline,
    flow_to_timeline,
    hostname_to_timeline,
    http_response_to_timeline,
    http_to_timeline,
    http_transaction_to_timeline,
    observation_to_timeline,
    relationship_to_timeline,
    service_to_timeline,
    sort_timeline,
    tls_client_hello_to_timeline,
    tls_server_hello_to_timeline,
    tls_transaction_to_timeline,
    tls_certificate_to_timeline,
    smb_file_operation_to_timeline,
    smb_session_setup_to_timeline,
    smb_tree_connect_to_timeline,
    smb_transaction_to_timeline,
)


TIMESTAMP = datetime(
    2026,
    1,
    1,
    tzinfo=timezone.utc,
)


def test_connection_to_timeline():
    connection = Connection(
        source=Endpoint(
            ip="10.10.10.42",
            port=49152,
        ),
        destination=Endpoint(
            ip="10.10.10.20",
            port=80,
        ),
        protocol="tcp",
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    record = connection_to_timeline(
        connection
    )

    assert isinstance(
        record,
        TimelineRecord,
    )
    assert record.timestamp == TIMESTAMP
    assert record.record_type == "connection"
    assert record.data["type"] == "connection"


def test_flow_to_timeline():
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
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
        packets=4,
        bytes=500,
        initiator=Endpoint(
            ip="10.10.10.42",
            port=49152,
        ),
        responder=Endpoint(
            ip="10.10.10.20",
            port=80,
        ),
        initiator_packets=2,
        initiator_bytes=200,
        responder_packets=2,
        responder_bytes=300,
    )

    record = flow_to_timeline(flow)

    assert record.timestamp == TIMESTAMP
    assert record.record_type == "flow"
    assert record.data["type"] == "flow"
    assert record.data["initiator_ip"] == (
        "10.10.10.42"
    )
    assert record.data["responder_ip"] == (
        "10.10.10.20"
    )


def test_dns_to_timeline():
    query = DNSQuery(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    record = dns_to_timeline(query)

    assert record.timestamp == TIMESTAMP
    assert record.record_type == "dns_query"
    assert record.data["type"] == "dns_query"
    assert record.data["name"] == (
        "fileserver.corp.local"
    )


def test_dns_transaction_to_timeline():
    query = DNSQuery(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    transaction = DNSTransaction(
        timestamp=TIMESTAMP,
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

    record = dns_transaction_to_timeline(
        transaction
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "dns_transaction"
    )
    assert (
        record.data["query"]["name"]
        == "fileserver.corp.local"
    )


def test_http_request_to_timeline():
    request = HTTPRequest(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        method="GET",
        host="example.com",
        path="/",
        version="HTTP/1.1",
        user_agent="TestAgent",
    )

    record = http_to_timeline(request)

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "http_request"
    )
    assert record.data["method"] == "GET"


def test_http_response_to_timeline():
    response = HTTPResponse(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="HTTP/1.1",
        status_code=200,
        reason="OK",
        server="nginx",
        content_type="text/html",
        content_length=100,
        location=None,
    )

    record = http_response_to_timeline(
        response
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "http_response"
    )
    assert record.data["status_code"] == 200


def test_http_transaction_to_timeline():
    request = HTTPRequest(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        method="GET",
        host="example.com",
        path="/",
        version="HTTP/1.1",
        user_agent=None,
    )

    response = HTTPResponse(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="HTTP/1.1",
        status_code=200,
        reason="OK",
        server="nginx",
        content_type="text/html",
        content_length=100,
        location=None,
    )

    transaction = HTTPTransaction(
        request=request,
        response=response,
    )

    record = http_transaction_to_timeline(
        transaction
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "http_transaction"
    )
    assert (
        record.data["request"]["method"]
        == "GET"
    )
    assert (
        record.data["response"]["status_code"]
        == 200
    )


def test_hostname_to_timeline():
    hostname = Hostname(
        name="fileserver.corp.local",
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    record = hostname_to_timeline(
        hostname
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == "hostname"
    assert record.data["name"] == (
        "fileserver.corp.local"
    )


def test_service_to_timeline():
    service = Service(
        host_ip="10.10.10.20",
        port=443,
        protocol="tcp",
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    record = service_to_timeline(service)

    assert record.timestamp == TIMESTAMP
    assert record.record_type == "service"
    assert record.data["host_ip"] == (
        "10.10.10.20"
    )
    assert record.data["port"] == 443


def test_relationship_to_timeline():
    relationship = Relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.42",
        ),
        relation="connects_to",
        target=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    record = relationship_to_timeline(
        relationship
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "relationship"
    )
    assert (
        record.data["source"]
        == "host:10.10.10.42"
    )
    assert (
        record.data["target"]
        == "host:10.10.10.20"
    )


def test_tls_client_hello_to_timeline():
    hello = TLSClientHello(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=443,
        version="TLS 1.2",
        server_name="example.com",
        alpn_protocols=["h2", "http/1.1"],
        cipher_suites=["0xc02f"],
    )

    record = tls_client_hello_to_timeline(
        hello
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "tls_client_hello"
    )
    assert (
        record.data["server_name"]
        == "example.com"
    )
    assert record.data["version"] == "TLS 1.2"


def test_tls_server_hello_to_timeline():
    hello = TLSServerHello(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.20",
        source_port=443,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="TLS 1.2",
        cipher_suite="0xc02f",
        alpn_protocol="h2",
    )

    record = tls_server_hello_to_timeline(
        hello
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "tls_server_hello"
    )
    assert (
        record.data["cipher_suite"]
        == "0xc02f"
    )
    assert (
        record.data["alpn_protocol"]
        == "h2"
    )


def test_tls_transaction_to_timeline():
    client_hello = TLSClientHello(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=443,
        version="TLS 1.2",
        server_name="example.com",
        alpn_protocols=["h2"],
        cipher_suites=["0xc02f"],
    )

    server_hello = TLSServerHello(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.20",
        source_port=443,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="TLS 1.2",
        cipher_suite="0xc02f",
        alpn_protocol="h2",
    )

    transaction = TLSTransaction(
        client_hello=client_hello,
        server_hello=server_hello,
    )

    record = tls_transaction_to_timeline(
        transaction
    )

    assert record.timestamp == TIMESTAMP
    assert record.record_type == (
        "tls_transaction"
    )

    assert (
        record.data["client_hello"]
        is not None
    )

    assert (
        record.data["server_hello"]
        is not None
    )


def test_observation_to_timeline_tls_client_hello():
    hello = TLSClientHello(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=443,
        version="TLS 1.2",
        server_name="example.com",
        alpn_protocols=["h2"],
        cipher_suites=["0xc02f"],
    )

    record = observation_to_timeline(
        hello
    )

    assert record.record_type == (
        "tls_client_hello"
    )


def test_observation_to_timeline_tls_server_hello():
    hello = TLSServerHello(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.20",
        source_port=443,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="TLS 1.2",
        cipher_suite="0xc02f",
        alpn_protocol="h2",
    )

    record = observation_to_timeline(
        hello
    )

    assert record.record_type == (
        "tls_server_hello"
    )


def test_observation_to_timeline_rejects_unknown_type():
    with pytest.raises(TypeError):
        observation_to_timeline(
            object()
        )


def test_sort_timeline():
    earlier = TimelineRecord(
        timestamp=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        record_type="earlier",
        data={},
    )

    later = TimelineRecord(
        timestamp=datetime(
            2026,
            1,
            2,
            tzinfo=timezone.utc,
        ),
        record_type="later",
        data={},
    )

    result = sort_timeline(
        [later, earlier]
    )

    assert result == [
        earlier,
        later,
    ]


def test_tls_certificate_to_timeline():
    certificate = TLSCertificate(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.20",
        source_port=443,
        destination_ip="10.10.10.42",
        destination_port=49152,
        fingerprint_sha256="abc123",
        subject="CN=example.com",
        issuer="CN=Example CA",
        serial_number="12345",
        not_before=TIMESTAMP,
        not_after=TIMESTAMP,
        subject_alt_names=["example.com"],
    )

    record = tls_certificate_to_timeline(
        certificate
    )

    assert record.timestamp == TIMESTAMP

    assert record.record_type == (
        "tls_certificate"
    )

    assert (
        record.data["fingerprint_sha256"]
        == "abc123"
    )


def test_smb_session_setup_to_timeline():
    observation = SMBSessionSetup(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="SESSION_SETUP",
        message_type="request",
        message_id=1,
        session_id=123,
        username="alice",
        domain="CORP",
        workstation="WS01",
    )

    result = smb_session_setup_to_timeline(
        observation
    )

    assert result.timestamp == TIMESTAMP
    assert result.record_type == (
        "smb_session_setup"
    )

    assert result.data["type"] == (
        "smb_session_setup"
    )

    assert result.data["identity"] == (
        r"CORP\alice"
    )


def test_smb_tree_connect_to_timeline():
    observation = SMBTreeConnect(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="TREE_CONNECT",
        message_type="request",
        message_id=2,
        session_id=123,
        tree_id=456,
        share=r"\\10.10.10.30\ADMIN$",
        share_type=None,
    )

    result = smb_tree_connect_to_timeline(
        observation
    )

    assert result.timestamp == TIMESTAMP
    assert result.record_type == (
        "smb_tree_connect"
    )

    assert result.data["type"] == (
        "smb_tree_connect"
    )

    assert result.data["share"] == (
        r"\\10.10.10.30\ADMIN$"
    )


def test_smb_file_operation_to_timeline():
    operation = SMBFileOperation(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="WRITE",
        message_type="request",
        message_id=11,
        session_id=123,
        tree_id=456,
        operation="WRITE",
        file_id=(
            "00112233445566778899aabbccddeeff"
        ),
        resolved_path=r"\Temp\payload.exe",
        offset=16384,
        length=2048,
        identity=r"CORP\alice",
        share=r"\\10.10.10.30\ADMIN$",
    )

    result = smb_file_operation_to_timeline(
        operation
    )

    assert result.timestamp == TIMESTAMP
    assert result.record_type == (
        "smb_file_operation"
    )

    assert result.data["type"] == (
        "smb_file_operation"
    )

    assert result.data["operation"] == "WRITE"
    assert result.data["resolved_path"] == (
        r"\Temp\payload.exe"
    )
    assert result.data["offset"] == 16384
    assert result.data["length"] == 2048
    assert result.data["identity"] == (
        r"CORP\alice"
    )
    assert result.data["share"] == (
        r"\\10.10.10.30\ADMIN$"
    )


def test_observation_to_timeline_supports_smb():
    session_setup = SMBSessionSetup(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="SESSION_SETUP",
        message_type="request",
        message_id=1,
        session_id=123,
        username="alice",
        domain="CORP",
        workstation="WS01",
    )

    tree_connect = SMBTreeConnect(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="TREE_CONNECT",
        message_type="request",
        message_id=2,
        session_id=123,
        tree_id=456,
        share=r"\\10.10.10.30\ADMIN$",
        share_type=None,
    )

    file_operation = SMBFileOperation(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="WRITE",
        message_type="request",
        message_id=11,
        session_id=123,
        tree_id=456,
        operation="WRITE",
        file_id=(
            "00112233445566778899aabbccddeeff"
        ),
        resolved_path=r"\Temp\payload.exe",
        offset=16384,
        length=2048,
        identity=r"CORP\alice",
        share=r"\\10.10.10.30\ADMIN$",
    )

    assert (
        observation_to_timeline(
            session_setup
        ).record_type
        == "smb_session_setup"
    )

    assert (
        observation_to_timeline(
            tree_connect
        ).record_type
        == "smb_tree_connect"
    )

    assert (
        observation_to_timeline(
            file_operation
        ).record_type
        == "smb_file_operation"
    )


def test_smb_transaction_to_timeline():
    request = SMBTreeConnect(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="TREE_CONNECT",
        message_type="request",
        message_id=2,
        session_id=123,
        tree_id=456,
        share=r"\\10.10.10.30\ADMIN$",
        share_type=None,
    )

    response = SMBTreeConnect(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.30",
        source_port=445,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="SMB3",
        command="TREE_CONNECT",
        message_type="response",
        message_id=2,
        session_id=123,
        tree_id=456,
        share=r"\\10.10.10.30\ADMIN$",
        share_type="DISK",
    )

    transaction = SMBTransaction(
        request=request,
        response=response,
    )

    result = smb_transaction_to_timeline(
        transaction
    )

    assert result.timestamp == TIMESTAMP

    assert result.record_type == (
        "smb_transaction"
    )

    assert result.data["type"] == (
        "smb_transaction"
    )

    assert result.data["request"] is not None
    assert result.data["response"] is not None

    assert result.data["request"]["message_type"] == (
        "request"
    )

    assert result.data["response"]["message_type"] == (
        "response"
    )