import json
from datetime import datetime, timezone

from wiretap.capture.flow import Flow
from wiretap.models import (
    Connection,
    DNSQuery,
    DNSAnswer,
    DNSTransaction,
    Endpoint,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
)
from wiretap.output.jsonl import (
    connection_to_dict,
    dns_query_to_dict,
    flow_to_dict,
    http_request_to_dict,
    http_response_to_dict,
    http_transaction_to_dict,
    serialize_connection,
    serialize_dns_query,
    serialize_flow,
    serialize_http_request,
    serialize_http_response,
    serialize_http_transaction,
    dns_transaction_to_dict,
    serialize_dns_transaction,
)


def test_connection_to_dict():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

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
        first_seen=timestamp,
        last_seen=timestamp,
        packets=1,
        bytes=60,
        tcp_flags=0x02,
    )

    result = connection_to_dict(connection)

    assert result["type"] == "connection"
    assert result["source"]["ip"] == "10.10.10.42"
    assert result["source"]["port"] == 49152
    assert result["destination"]["ip"] == "10.10.10.20"
    assert result["destination"]["port"] == 80
    assert result["protocol"] == "tcp"
    assert result["packets"] == 1
    assert result["bytes"] == 60


def test_serialize_connection():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

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
        first_seen=timestamp,
        last_seen=timestamp,
        packets=1,
        bytes=60,
        tcp_flags=0x02,
    )

    result = json.loads(
        serialize_connection(connection)
    )

    assert result["type"] == "connection"
    assert result["source"]["ip"] == "10.10.10.42"
    assert result["source"]["port"] == 49152
    assert result["destination"]["ip"] == "10.10.10.20"
    assert result["destination"]["port"] == 80


def test_dns_query_to_dict():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    query = DNSQuery(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="1",
    )

    result = dns_query_to_dict(query)

    assert result["type"] == "dns_query"
    assert result["timestamp"] == "2026-09-30T12:00:00Z"
    assert result["source"]["ip"] == "10.10.10.42"
    assert result["destination"]["ip"] == "10.10.10.10"
    assert result["query"] == "fileserver.corp.local"
    assert result["query_type"] == "1"


def test_serialize_dns_query():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    query = DNSQuery(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="1",
    )

    result = json.loads(
        serialize_dns_query(query)
    )

    assert result["type"] == "dns_query"
    assert result["query"] == "fileserver.corp.local"


def test_flow_to_dict():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    client = Endpoint(
        ip="10.10.10.42",
        port=49152,
    )

    server = Endpoint(
        ip="10.10.10.20",
        port=80,
    )

    flow = Flow(
        endpoint_a=client,
        endpoint_b=server,
        protocol="tcp",
        first_seen=timestamp,
        last_seen=timestamp,
        packets=3,
        bytes=174,
        initiator=client,
        responder=server,
        initiator_packets=2,
        initiator_bytes=114,
        responder_packets=1,
        responder_bytes=60,
    )

    result = flow_to_dict(flow)

    assert result["type"] == "flow"
    assert result["protocol"] == "tcp"
    assert result["packets"] == 3
    assert result["bytes"] == 174

    assert result["initiator"]["ip"] == "10.10.10.42"
    assert result["initiator"]["port"] == 49152

    assert result["responder"]["ip"] == "10.10.10.20"
    assert result["responder"]["port"] == 80


def test_serialize_flow():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    client = Endpoint(
        ip="10.10.10.42",
        port=49152,
    )

    server = Endpoint(
        ip="10.10.10.20",
        port=80,
    )

    flow = Flow(
        endpoint_a=client,
        endpoint_b=server,
        protocol="tcp",
        first_seen=timestamp,
        last_seen=timestamp,
        packets=3,
        bytes=174,
        initiator=client,
        responder=server,
        initiator_packets=2,
        initiator_bytes=114,
        responder_packets=1,
        responder_bytes=60,
    )

    result = json.loads(
        serialize_flow(flow)
    )

    assert result["type"] == "flow"
    assert result["initiator"]["ip"] == "10.10.10.42"
    assert result["initiator"]["port"] == 49152


def test_http_request_to_dict():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request = HTTPRequest(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        method="GET",
        host="fileserver.corp.local",
        path="/admin/login",
        version="HTTP/1.1",
        user_agent="WiretapTest/1.0",
    )

    result = http_request_to_dict(request)

    assert result["type"] == "http_request"
    assert result["timestamp"] == "2026-09-30T12:00:00Z"

    assert result["source"]["ip"] == "10.10.10.42"
    assert result["source"]["port"] == 49152

    assert result["destination"]["ip"] == "10.10.10.20"
    assert result["destination"]["port"] == 80

    assert result["method"] == "GET"
    assert result["host"] == "fileserver.corp.local"
    assert result["path"] == "/admin/login"
    assert result["version"] == "HTTP/1.1"
    assert result["user_agent"] == "WiretapTest/1.0"


def test_serialize_http_request():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request = HTTPRequest(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        method="GET",
        host="fileserver.corp.local",
        path="/admin/login",
        version="HTTP/1.1",
        user_agent="WiretapTest/1.0",
    )

    result = json.loads(
        serialize_http_request(request)
    )

    assert result["type"] == "http_request"
    assert result["source"]["ip"] == "10.10.10.42"
    assert result["source"]["port"] == 49152
    assert result["destination"]["ip"] == "10.10.10.20"
    assert result["destination"]["port"] == 80
    assert result["method"] == "GET"
    assert result["host"] == "fileserver.corp.local"
    assert result["path"] == "/admin/login"


def test_http_response_to_dict():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    response = HTTPResponse(
        timestamp=timestamp,
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="HTTP/1.1",
        status_code=200,
        reason="OK",
        server="nginx/1.24.0",
        content_type="text/html",
        content_length=18432,
        location=None,
    )

    result = http_response_to_dict(response)

    assert result["type"] == "http_response"
    assert result["timestamp"] == "2026-09-30T12:00:00Z"

    assert result["source"]["ip"] == "10.10.10.20"
    assert result["source"]["port"] == 80

    assert result["destination"]["ip"] == "10.10.10.42"
    assert result["destination"]["port"] == 49152

    assert result["version"] == "HTTP/1.1"
    assert result["status_code"] == 200
    assert result["reason"] == "OK"
    assert result["server"] == "nginx/1.24.0"
    assert result["content_type"] == "text/html"
    assert result["content_length"] == 18432
    assert result["location"] is None


def test_serialize_http_response():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    response = HTTPResponse(
        timestamp=timestamp,
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="HTTP/1.1",
        status_code=200,
        reason="OK",
        server="nginx/1.24.0",
        content_type="text/html",
        content_length=18432,
        location=None,
    )

    result = json.loads(
        serialize_http_response(response)
    )

    assert result["type"] == "http_response"
    assert result["source"]["ip"] == "10.10.10.20"
    assert result["source"]["port"] == 80
    assert result["destination"]["ip"] == "10.10.10.42"
    assert result["destination"]["port"] == 49152
    assert result["status_code"] == 200


def test_http_transaction_to_dict():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request = HTTPRequest(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        method="GET",
        host="fileserver.corp.local",
        path="/admin/login",
        version="HTTP/1.1",
        user_agent="WiretapTest/1.0",
    )

    response = HTTPResponse(
        timestamp=timestamp,
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="HTTP/1.1",
        status_code=200,
        reason="OK",
        server="nginx/1.24.0",
        content_type="text/html",
        content_length=18432,
        location=None,
    )

    transaction = HTTPTransaction(
        request=request,
        response=response,
    )

    result = http_transaction_to_dict(transaction)

    assert result["type"] == "http_transaction"

    assert result["request"]["type"] == "http_request"
    assert result["request"]["method"] == "GET"
    assert result["request"]["path"] == "/admin/login"

    assert result["response"]["type"] == "http_response"
    assert result["response"]["status_code"] == 200
    assert result["response"]["server"] == "nginx/1.24.0"


def test_serialize_http_transaction():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    request = HTTPRequest(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        method="GET",
        host="fileserver.corp.local",
        path="/admin/login",
        version="HTTP/1.1",
        user_agent="WiretapTest/1.0",
    )

    response = HTTPResponse(
        timestamp=timestamp,
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="HTTP/1.1",
        status_code=200,
        reason="OK",
        server="nginx/1.24.0",
        content_type="text/html",
        content_length=18432,
        location=None,
    )

    transaction = HTTPTransaction(
        request=request,
        response=response,
    )

    result = json.loads(
        serialize_http_transaction(transaction)
    )

    assert result["type"] == "http_transaction"
    assert result["request"]["source"]["port"] == 49152
    assert result["response"]["source"]["port"] == 80
    assert result["response"]["status_code"] == 200


def test_dns_transaction_to_dict():
    query = DNSQuery(
        timestamp=datetime(
            2026,
            9,
            30,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    transaction = DNSTransaction(
        timestamp=query.timestamp,
        source_ip=query.source_ip,
        destination_ip=query.destination_ip,
        query=query,
        answers=[
            DNSAnswer(
                name="fileserver.corp.local",
                record_type="A",
                value="10.10.10.20",
                ttl=300,
            ),
        ],
        response_code=0,
    )

    result = dns_transaction_to_dict(transaction)

    assert result["type"] == "dns_transaction"
    assert result["source"]["ip"] == "10.10.10.42"
    assert result["destination"]["ip"] == "10.10.10.10"

    assert result["query"]["name"] == "fileserver.corp.local"
    assert result["query"]["type"] == "A"
    assert result["query"]["transaction_id"] == 1234

    assert result["response_code"] == 0

    assert result["answers"] == [
        {
            "name": "fileserver.corp.local",
            "type": "A",
            "value": "10.10.10.20",
            "ttl": 300,
        }
    ]


def test_serialize_dns_transaction():
    query = DNSQuery(
        timestamp=datetime(
            2026,
            9,
            30,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        source_ip="10.10.10.42",
        destination_ip="10.10.10.10",
        query="fileserver.corp.local",
        query_type="A",
        transaction_id=1234,
    )

    transaction = DNSTransaction(
        timestamp=query.timestamp,
        source_ip=query.source_ip,
        destination_ip=query.destination_ip,
        query=query,
        answers=[
            DNSAnswer(
                name="fileserver.corp.local",
                record_type="A",
                value="10.10.10.20",
                ttl=300,
            ),
        ],
        response_code=0,
    )

    result = json.loads(
        serialize_dns_transaction(transaction)
    )

    assert result["type"] == "dns_transaction"
    assert result["query"]["transaction_id"] == 1234
    assert result["answers"][0]["value"] == "10.10.10.20"


def test_relationship_to_dict():
    from datetime import datetime, timezone

    from wiretap.models import Relationship
    from wiretap.output.jsonl import relationship_to_dict

    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    relationship = Relationship(
        source="10.10.10.42",
        relation="queried",
        target="fileserver.corp.local",
        first_seen=timestamp,
        last_seen=timestamp,
    )

    result = relationship_to_dict(relationship)

    assert result == {
        "type": "relationship",
        "timestamp": "2026-01-01T00:00:01Z",
        "first_seen": "2026-01-01T00:00:01Z",
        "last_seen": "2026-01-01T00:00:01Z",
        "source": "10.10.10.42",
        "relation": "queried",
        "target": "fileserver.corp.local",
    }


def test_serialize_relationship():
    from datetime import datetime, timezone

    from wiretap.models import Relationship
    from wiretap.output.jsonl import serialize_relationship

    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    relationship = Relationship(
        source="fileserver.corp.local",
        relation="resolves_to",
        target="10.10.10.20",
        first_seen=timestamp,
        last_seen=timestamp,
    )

    result = serialize_relationship(relationship)

    assert '"type":"relationship"' in result
    assert '"relation":"resolves_to"' in result
    assert '"source":"fileserver.corp.local"' in result
    assert '"target":"10.10.10.20"' in result


def test_hostname_to_dict():
    from datetime import datetime, timezone

    from wiretap.models import Hostname
    from wiretap.output.jsonl import hostname_to_dict

    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    hostname = Hostname(
        name="fileserver.corp.local",
        first_seen=timestamp,
        last_seen=timestamp,
    )

    result = hostname_to_dict(hostname)

    assert result == {
        "type": "hostname",
        "timestamp": "2026-01-01T00:00:01Z",
        "first_seen": "2026-01-01T00:00:01Z",
        "last_seen": "2026-01-01T00:00:01Z",
        "name": "fileserver.corp.local",
    }