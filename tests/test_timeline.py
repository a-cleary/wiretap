from datetime import datetime, timedelta, timezone

from wiretap.capture.flow import Flow
from wiretap.models import (
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
)
from wiretap.output.timeline import (
    TimelineRecord,
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
)


def test_flow_to_timeline():
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

    record = flow_to_timeline(flow)

    assert record.timestamp == timestamp
    assert record.record_type == "flow"
    assert record.data["type"] == "flow"

    assert record.data["initiator_ip"] == (
        "10.10.10.42"
    )

    assert record.data["initiator_port"] == 49152

    assert record.data["responder_ip"] == (
        "10.10.10.20"
    )

    assert record.data["responder_port"] == 80

    assert record.data["packets"] == 3
    assert record.data["bytes"] == 174


def test_observation_to_timeline_dns():
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

    record = observation_to_timeline(query)

    assert record.timestamp == timestamp
    assert record.record_type == "dns_query"
    assert record.data["type"] == "dns_query"

    assert record.data["name"] == (
        "fileserver.corp.local"
    )

    assert record.data["source_ip"] == (
        "10.10.10.42"
    )

    assert record.data["destination_ip"] == (
        "10.10.10.10"
    )


def test_observation_to_timeline_http():
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

    record = observation_to_timeline(request)

    assert record.timestamp == timestamp
    assert record.record_type == "http_request"
    assert record.data["type"] == "http_request"

    assert record.data["source_ip"] == (
        "10.10.10.42"
    )

    assert record.data["source_port"] == 49152

    assert record.data["destination_ip"] == (
        "10.10.10.20"
    )

    assert record.data["destination_port"] == 80

    assert record.data["method"] == "GET"
    assert record.data["host"] == (
        "fileserver.corp.local"
    )
    assert record.data["path"] == "/admin/login"


def test_observation_to_timeline_http_response():
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

    record = observation_to_timeline(response)

    assert record.timestamp == timestamp
    assert record.record_type == "http_response"
    assert record.data["type"] == "http_response"

    assert record.data["source_ip"] == (
        "10.10.10.20"
    )

    assert record.data["source_port"] == 80

    assert record.data["destination_ip"] == (
        "10.10.10.42"
    )

    assert record.data["destination_port"] == 49152

    assert record.data["status_code"] == 200
    assert record.data["server"] == "nginx/1.24.0"


def test_http_transaction_to_timeline():
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
        timestamp=timestamp + timedelta(seconds=1),
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

    record = http_transaction_to_timeline(
        transaction
    )

    assert record.timestamp == timestamp
    assert record.record_type == "http_transaction"
    assert record.data["type"] == "http_transaction"

    assert record.data["request"]["method"] == "GET"
    assert record.data["request"]["host"] == (
        "fileserver.corp.local"
    )

    assert record.data["response"]["status_code"] == 200
    assert record.data["response"]["server"] == (
        "nginx/1.24.0"
    )


def test_dns_transaction_to_timeline():
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

    record = dns_transaction_to_timeline(
        transaction
    )

    assert record.timestamp == timestamp
    assert record.record_type == "dns_transaction"
    assert record.data["type"] == "dns_transaction"

    assert record.data["query"]["name"] == (
        "fileserver.corp.local"
    )

    assert record.data["query"]["type"] == "A"

    assert record.data["query"]["transaction_id"] == 1234

    assert record.data["answers"][0]["value"] == (
        "10.10.10.20"
    )


def test_hostname_to_timeline():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    hostname = Hostname(
        name="fileserver.corp.local",
        first_seen=timestamp,
        last_seen=timestamp,
    )

    record = hostname_to_timeline(hostname)

    assert record.timestamp == timestamp
    assert record.record_type == "hostname"
    assert record.data["type"] == "hostname"

    assert record.data["name"] == (
        "fileserver.corp.local"
    )


def test_service_to_timeline():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    service = Service(
        host_ip="10.10.10.20",
        port=80,
        protocol="tcp",
        first_seen=timestamp,
        last_seen=timestamp,
    )

    record = service_to_timeline(service)

    assert record.timestamp == timestamp
    assert record.record_type == "service"
    assert record.data["type"] == "service"

    assert record.data["host_ip"] == (
        "10.10.10.20"
    )

    assert record.data["port"] == 80
    assert record.data["protocol"] == "tcp"
    assert record.data["id"] == "service:tcp/80"


def test_relationship_to_timeline():
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
        source=EntityRef(
            type="host",
            value="10.10.10.42",
        ),
        relation="queried",
        target=EntityRef(
            type="hostname",
            value="fileserver.corp.local",
        ),
        first_seen=timestamp,
        last_seen=timestamp,
    )

    record = relationship_to_timeline(
        relationship
    )

    assert record.timestamp == timestamp
    assert record.record_type == "relationship"
    assert record.data["type"] == "relationship"

    assert record.data["source"] == (
        "host:10.10.10.42"
    )

    assert record.data["source_type"] == "host"

    assert record.data["target"] == (
        "hostname:fileserver.corp.local"
    )

    assert record.data["target_type"] == "hostname"

    assert record.data["relation"] == "queried"


def test_sort_timeline():
    first_timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        1,
        tzinfo=timezone.utc,
    )

    second_timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        2,
        tzinfo=timezone.utc,
    )

    third_timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        3,
        tzinfo=timezone.utc,
    )

    records = [
        TimelineRecord(
            timestamp=third_timestamp,
            record_type="third",
            data={},
        ),
        TimelineRecord(
            timestamp=first_timestamp,
            record_type="first",
            data={},
        ),
        TimelineRecord(
            timestamp=second_timestamp,
            record_type="second",
            data={},
        ),
    ]

    sorted_records = sort_timeline(records)

    assert [
        record.record_type
        for record in sorted_records
    ] == [
        "first",
        "second",
        "third",
    ]