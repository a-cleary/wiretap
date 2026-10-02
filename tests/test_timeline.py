from datetime import datetime, timedelta, timezone

from wiretap.capture.flow import Flow
from wiretap.models import (
    DNSQuery,
    Endpoint,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    Relationship,
    EntityRef,
)
from wiretap.output.timeline import (
    dns_to_timeline,
    flow_to_timeline,
    http_to_timeline,
    http_response_to_timeline,
    http_transaction_to_timeline,
    observation_to_timeline,
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
    assert record.data["initiator"]["ip"] == "10.10.10.42"
    assert record.data["responder"]["ip"] == "10.10.10.20"


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
    assert record.data["query"] == "fileserver.corp.local"


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

    assert record.data["source"]["ip"] == "10.10.10.42"
    assert record.data["source"]["port"] == 49152

    assert record.data["destination"]["ip"] == "10.10.10.20"
    assert record.data["destination"]["port"] == 80

    assert record.data["method"] == "GET"
    assert record.data["host"] == "fileserver.corp.local"
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

    assert record.data["source"]["ip"] == "10.10.10.20"
    assert record.data["source"]["port"] == 80

    assert record.data["destination"]["ip"] == "10.10.10.42"
    assert record.data["destination"]["port"] == 49152

    assert record.data["status_code"] == 200
    assert record.data["reason"] == "OK"
    assert record.data["server"] == "nginx/1.24.0"


def test_sort_timeline():
    start = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    records = [
        (
            start + timedelta(seconds=30),
            "http_request",
        ),
        (
            start,
            "dns_query",
        ),
        (
            start + timedelta(seconds=10),
            "flow",
        ),
    ]

    timeline_records = []

    for timestamp, record_type in records:
        timeline_records.append(
            type(
                "TimelineRecord",
                (),
                {
                    "timestamp": timestamp,
                    "record_type": record_type,
                    "data": {},
                },
            )()
        )

    sorted_records = sort_timeline(
        timeline_records
    )

    assert [
        record.record_type
        for record in sorted_records
    ] == [
        "dns_query",
        "flow",
        "http_request",
    ]


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

    record = http_transaction_to_timeline(transaction)

    assert record.record_type == "http_transaction"
    assert record.timestamp == timestamp
    assert record.data["request"]["path"] == "/admin/login"
    assert record.data["response"]["status_code"] == 200


def test_relationship_to_timeline():
    from datetime import datetime, timezone

    from wiretap.models import Relationship
    from wiretap.output.timeline import (
        relationship_to_timeline,
    )

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
    assert record.data["relation"] == "queried"