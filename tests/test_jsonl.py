import json
from datetime import datetime, timezone

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
    SMBNegotiate,
)
from wiretap.output.jsonl import (
    connection_to_dict,
    dns_query_to_dict,
    dns_transaction_to_dict,
    flow_to_dict,
    hostname_to_dict,
    http_request_to_dict,
    http_response_to_dict,
    http_transaction_to_dict,
    relationship_to_dict,
    serialize_connection,
    serialize_dns_query,
    serialize_dns_transaction,
    serialize_flow,
    serialize_hostname,
    serialize_http_request,
    serialize_http_response,
    serialize_http_transaction,
    serialize_relationship,
    serialize_service,
    serialize_tls_client_hello,
    serialize_tls_server_hello,
    serialize_tls_transaction,
    service_to_dict,
    tls_client_hello_to_dict,
    tls_server_hello_to_dict,
    tls_transaction_to_dict,
    serialize_tls_certificate,
    tls_certificate_to_dict,
    serialize_smb_file_operation,
    serialize_smb_session_setup,
    serialize_smb_tree_connect,
    smb_file_operation_to_dict,
    smb_session_setup_to_dict,
    smb_tree_connect_to_dict,
    smb_observation_to_dict,
    smb_transaction_to_dict,
    serialize_smb_transaction,
    serialize_smb_negotiate,
    smb_negotiate_to_dict,
)
from wiretap.capture.flow import Flow


TIMESTAMP = datetime(
    2026,
    1,
    1,
    tzinfo=timezone.utc,
)


def test_connection_to_dict():
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
        packets=2,
        bytes=120,
        tcp_flags=0x12,
    )

    result = connection_to_dict(connection)

    assert result["type"] == "connection"
    assert result["source_ip"] == "10.10.10.42"
    assert result["source_port"] == 49152
    assert result["destination_ip"] == "10.10.10.20"
    assert result["destination_port"] == 80
    assert result["protocol"] == "tcp"
    assert result["packets"] == 2
    assert result["bytes"] == 120


def test_connection_serializes_as_json():
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

    result = serialize_connection(connection)

    parsed = json.loads(result)

    assert parsed["type"] == "connection"
    assert parsed["source_ip"] == "10.10.10.42"


def test_dns_query_to_dict():
    query = DNSQuery(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    result = dns_query_to_dict(query)

    assert result["type"] == "dns_query"
    assert result["name"] == "fileserver.corp.local"
    assert result["query_type"] == "A"
    assert result["transaction_id"] == 1234


def test_dns_query_serializes_as_json():
    query = DNSQuery(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    result = serialize_dns_query(query)

    parsed = json.loads(result)

    assert parsed["type"] == "dns_query"
    assert parsed["name"] == "fileserver.corp.local"


def test_dns_transaction_to_dict():
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

    result = dns_transaction_to_dict(
        transaction
    )

    assert result["type"] == "dns_transaction"
    assert result["query"]["name"] == (
        "fileserver.corp.local"
    )
    assert len(result["answers"]) == 1
    assert result["answers"][0]["value"] == (
        "10.10.10.20"
    )


def test_dns_transaction_serializes_as_json():
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
        answers=[],
        response_code=0,
    )

    result = serialize_dns_transaction(
        transaction
    )

    parsed = json.loads(result)

    assert parsed["type"] == "dns_transaction"


def test_flow_to_dict():
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

    result = flow_to_dict(flow)

    assert result["type"] == "flow"
    assert result["initiator_ip"] == "10.10.10.42"
    assert result["initiator_port"] == 49152
    assert result["responder_ip"] == "10.10.10.20"
    assert result["responder_port"] == 80
    assert result["packets"] == 4
    assert result["bytes"] == 500


def test_flow_serializes_as_json():
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
    )

    result = serialize_flow(flow)

    parsed = json.loads(result)

    assert parsed["type"] == "flow"


def test_hostname_to_dict():
    hostname = Hostname(
        name="fileserver.corp.local",
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    result = hostname_to_dict(hostname)

    assert result["type"] == "hostname"
    assert result["name"] == "fileserver.corp.local"


def test_hostname_serializes_as_json():
    hostname = Hostname(
        name="fileserver.corp.local",
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    result = serialize_hostname(hostname)

    parsed = json.loads(result)

    assert parsed["type"] == "hostname"


def test_service_to_dict():
    service = Service(
        host_ip="10.10.10.20",
        port=443,
        protocol="tcp",
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    result = service_to_dict(service)

    assert result["type"] == "service"
    assert result["host_ip"] == "10.10.10.20"
    assert result["port"] == 443
    assert result["protocol"] == "tcp"
    assert result["id"] == "service:tcp/443"


def test_service_serializes_as_json():
    service = Service(
        host_ip="10.10.10.20",
        port=443,
        protocol="tcp",
        first_seen=TIMESTAMP,
        last_seen=TIMESTAMP,
    )

    result = serialize_service(service)

    parsed = json.loads(result)

    assert parsed["type"] == "service"
    assert parsed["id"] == "service:tcp/443"


def test_http_request_to_dict():
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

    result = http_request_to_dict(request)

    assert result["type"] == "http_request"
    assert result["method"] == "GET"
    assert result["host"] == "example.com"
    assert result["path"] == "/"


def test_http_request_serializes_as_json():
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

    result = serialize_http_request(request)

    parsed = json.loads(result)

    assert parsed["type"] == "http_request"


def test_http_response_to_dict():
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

    result = http_response_to_dict(response)

    assert result["type"] == "http_response"
    assert result["status_code"] == 200
    assert result["server"] == "nginx"


def test_http_response_serializes_as_json():
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

    result = serialize_http_response(response)

    parsed = json.loads(result)

    assert parsed["type"] == "http_response"
    assert parsed["status_code"] == 200


def test_http_transaction_to_dict():
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

    result = http_transaction_to_dict(
        transaction
    )

    assert result["type"] == "http_transaction"
    assert result["request"]["method"] == "GET"
    assert result["response"]["status_code"] == 200


def test_http_transaction_serializes_as_json():
    transaction = HTTPTransaction()

    result = None

    if (
        transaction.request is None
        and transaction.response is None
    ):
        transaction = HTTPTransaction(
            request=HTTPRequest(
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
        )

        result = serialize_http_transaction(
            transaction
        )

    parsed = json.loads(result)

    assert parsed["type"] == "http_transaction"


def test_relationship_to_dict():
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

    result = relationship_to_dict(
        relationship
    )

    assert result["type"] == "relationship"
    assert result["source"] == "host:10.10.10.42"
    assert result["target"] == "host:10.10.10.20"
    assert result["relation"] == "connects_to"


def test_relationship_serializes_as_json():
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

    result = serialize_relationship(
        relationship
    )

    parsed = json.loads(result)

    assert parsed["type"] == "relationship"


def test_tls_client_hello_to_dict():
    hello = TLSClientHello(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=443,
        version="TLS 1.2",
        server_name="example.com",
        alpn_protocols=[
            "h2",
            "http/1.1",
        ],
        cipher_suites=[
            "0xc02f",
            "0xc02b",
        ],
    )

    result = tls_client_hello_to_dict(
        hello
    )

    assert result["type"] == "tls_client_hello"
    assert result["source_ip"] == "10.10.10.42"
    assert result["destination_port"] == 443
    assert result["version"] == "TLS 1.2"
    assert result["server_name"] == "example.com"
    assert result["alpn_protocols"] == [
        "h2",
        "http/1.1",
    ]
    assert result["cipher_suites"] == [
        "0xc02f",
        "0xc02b",
    ]


def test_tls_client_hello_serializes_as_json():
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

    result = serialize_tls_client_hello(
        hello
    )

    parsed = json.loads(result)

    assert parsed["type"] == "tls_client_hello"
    assert parsed["server_name"] == "example.com"


def test_tls_server_hello_to_dict():
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

    result = tls_server_hello_to_dict(
        hello
    )

    assert result["type"] == "tls_server_hello"
    assert result["source_ip"] == "10.10.10.20"
    assert result["destination_ip"] == "10.10.10.42"
    assert result["version"] == "TLS 1.2"
    assert result["cipher_suite"] == "0xc02f"
    assert result["alpn_protocol"] == "h2"


def test_tls_server_hello_serializes_as_json():
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

    result = serialize_tls_server_hello(
        hello
    )

    parsed = json.loads(result)

    assert parsed["type"] == "tls_server_hello"
    assert parsed["cipher_suite"] == "0xc02f"


def test_tls_transaction_to_dict():
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

    result = tls_transaction_to_dict(
        transaction
    )

    assert result["type"] == "tls_transaction"
    assert result["client_hello"] is not None
    assert result["server_hello"] is not None
    assert (
        result["client_hello"]["server_name"]
        == "example.com"
    )
    assert (
        result["server_hello"]["cipher_suite"]
        == "0xc02f"
    )


def test_tls_transaction_serializes_as_json():
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

    result = serialize_tls_transaction(
        transaction
    )

    parsed = json.loads(result)

    assert parsed["type"] == "tls_transaction"
    assert parsed["client_hello"] is not None
    assert parsed["server_hello"] is not None


def test_tls_certificate_to_dict():
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
        subject_alt_names=[
            "example.com",
            "www.example.com",
        ],
    )

    result = tls_certificate_to_dict(
        certificate
    )

    assert result["type"] == (
        "tls_certificate"
    )

    assert result["fingerprint_sha256"] == (
        "abc123"
    )

    assert result["subject"] == (
        "CN=example.com"
    )

    assert result["issuer"] == (
        "CN=Example CA"
    )

    assert result["subject_alt_names"] == [
        "example.com",
        "www.example.com",
    ]


def test_tls_certificate_serializes_as_json():
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

    result = serialize_tls_certificate(
        certificate
    )

    parsed = json.loads(result)

    assert parsed["type"] == (
        "tls_certificate"
    )

    assert parsed["fingerprint_sha256"] == (
        "abc123"
    )

def test_smb_session_setup_to_dict():
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
        tree_id=0,
        username="alice",
        domain="CORP",
        workstation="WS01",
    )

    result = smb_session_setup_to_dict(
        observation
    )

    assert result["type"] == (
        "smb_session_setup"
    )

    assert result["source_ip"] == (
        "10.10.10.42"
    )

    assert result["session_id"] == 123

    assert result["username"] == "alice"
    assert result["domain"] == "CORP"
    assert result["workstation"] == "WS01"

    assert result["identity"] == (
        r"CORP\alice"
    )


def test_smb_session_setup_serializes_as_json():
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

    result = serialize_smb_session_setup(
        observation
    )

    parsed = json.loads(result)

    assert parsed["type"] == (
        "smb_session_setup"
    )

    assert parsed["identity"] == (
        r"CORP\alice"
    )


def test_smb_tree_connect_to_dict():
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

    result = smb_tree_connect_to_dict(
        observation
    )

    assert result["type"] == (
        "smb_tree_connect"
    )

    assert result["session_id"] == 123
    assert result["tree_id"] == 456

    assert result["share"] == (
        r"\\10.10.10.30\ADMIN$"
    )


def test_smb_tree_connect_serializes_as_json():
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

    result = serialize_smb_tree_connect(
        observation
    )

    parsed = json.loads(result)

    assert parsed["type"] == (
        "smb_tree_connect"
    )

    assert parsed["share"] == (
        r"\\10.10.10.30\ADMIN$"
    )


def test_smb_file_operation_to_dict():
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
        path=None,
        filename=None,
        file_id=(
            "00112233445566778899aabbccddeeff"
        ),
        resolved_path=r"\Temp\payload.exe",
        offset=16384,
        length=2048,
        identity=r"CORP\alice",
        share=r"\\10.10.10.30\ADMIN$",
    )

    result = smb_file_operation_to_dict(
        operation
    )

    assert result["type"] == (
        "smb_file_operation"
    )

    assert result["operation"] == "WRITE"

    assert result["source_ip"] == (
        "10.10.10.42"
    )

    assert result["session_id"] == 123
    assert result["tree_id"] == 456

    assert result["file_id"] == (
        "00112233445566778899aabbccddeeff"
    )

    assert result["resolved_path"] == (
        r"\Temp\payload.exe"
    )

    assert result["offset"] == 16384
    assert result["length"] == 2048

    assert result["identity"] == (
        r"CORP\alice"
    )

    assert result["share"] == (
        r"\\10.10.10.30\ADMIN$"
    )


def test_smb_file_operation_serializes_as_json():
    operation = SMBFileOperation(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="READ",
        message_type="request",
        message_id=12,
        session_id=123,
        tree_id=456,
        operation="READ",
        file_id=(
            "00112233445566778899aabbccddeeff"
        ),
        resolved_path=r"\Temp\payload.exe",
        offset=8192,
        length=4096,
        identity=r"CORP\alice",
        share=r"\\10.10.10.30\ADMIN$",
    )

    result = serialize_smb_file_operation(
        operation
    )

    parsed = json.loads(result)

    assert parsed["type"] == (
        "smb_file_operation"
    )

    assert parsed["operation"] == "READ"

    assert parsed["resolved_path"] == (
        r"\Temp\payload.exe"
    )

    assert parsed["offset"] == 8192
    assert parsed["length"] == 4096

    assert parsed["identity"] == (
        r"CORP\alice"
    )

    assert parsed["share"] == (
        r"\\10.10.10.30\ADMIN$"
    )


def test_smb_transaction_to_dict():
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

    result = smb_transaction_to_dict(
        transaction
    )

    assert result["type"] == (
        "smb_transaction"
    )

    assert result["request"] is not None
    assert result["response"] is not None

    assert result["request"]["type"] == (
        "smb_tree_connect"
    )

    assert result["response"]["type"] == (
        "smb_tree_connect"
    )

    assert result["request"]["message_type"] == (
        "request"
    )

    assert result["response"]["message_type"] == (
        "response"
    )

    assert result["request"]["share"] == (
        r"\\10.10.10.30\ADMIN$"
    )

    assert result["response"]["share_type"] == (
        "DISK"
    )


def test_smb_transaction_serializes_as_json():
    request = SMBFileOperation(
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

    transaction = SMBTransaction(
        request=request,
    )

    result = serialize_smb_transaction(
        transaction
    )

    parsed = json.loads(result)

    assert parsed["type"] == (
        "smb_transaction"
    )

    assert parsed["response"] is None

    assert parsed["request"]["operation"] == (
        "WRITE"
    )

    assert parsed["request"]["resolved_path"] == (
        r"\Temp\payload.exe"
    )

    assert parsed["request"]["identity"] == (
        r"CORP\alice"
    )


def test_smb_negotiate_to_dict():
    observation = SMBNegotiate(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="NEGOTIATE",
        message_type="request",
        message_id=1,
        session_id=None,
        tree_id=None,
        dialect="SMB 3.1.1",
        dialects=[
            "SMB 2.1",
            "SMB 3.0",
            "SMB 3.1.1",
        ],
    )

    result = smb_negotiate_to_dict(
        observation
    )

    assert result["type"] == "smb_negotiate"
    assert result["source_ip"] == "10.10.10.42"
    assert result["destination_port"] == 445
    assert result["command"] == "NEGOTIATE"
    assert result["message_type"] == "request"
    assert result["dialect"] == "SMB 3.1.1"
    assert result["dialects"] == [
        "SMB 2.1",
        "SMB 3.0",
        "SMB 3.1.1",
    ]


def test_smb_negotiate_serializes_as_json():
    observation = SMBNegotiate(
        timestamp=TIMESTAMP,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="NEGOTIATE",
        message_type="response",
        message_id=1,
        session_id=None,
        tree_id=None,
        dialect="SMB 3.1.1",
        dialects=None,
    )

    result = serialize_smb_negotiate(
        observation
    )

    parsed = json.loads(result)

    assert parsed["type"] == "smb_negotiate"
    assert parsed["message_type"] == "response"
    assert parsed["dialect"] == "SMB 3.1.1"