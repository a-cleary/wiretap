from datetime import datetime, timedelta, timezone

from wiretap.capture.entities import EntityTracker
from wiretap.capture.flow import Flow
from wiretap.models import Endpoint


def make_flow(
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    timestamp: datetime,
) -> Flow:
    flow = Flow(
        endpoint_a=Endpoint(
            ip=min(source_ip, destination_ip),
            port=(
                source_port
                if source_ip < destination_ip
                else destination_port
            ),
        ),
        endpoint_b=Endpoint(
            ip=max(source_ip, destination_ip),
            port=(
                destination_port
                if source_ip < destination_ip
                else source_port
            ),
        ),
        protocol="tcp",
        first_seen=timestamp,
        last_seen=timestamp,
        initiator=Endpoint(
            ip=source_ip,
            port=source_port,
        ),
        responder=Endpoint(
            ip=destination_ip,
            port=destination_port,
        ),
    )

    return flow


def test_entity_tracker_discovers_hosts_and_responder_services():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    flow = make_flow(
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        timestamp=timestamp,
    )

    tracker = EntityTracker()

    tracker.add_flow(flow)

    hosts = tracker.hosts()
    services = tracker.services()

    assert len(hosts) == 2

    assert {
        host.ip
        for host in hosts
    } == {
        "10.10.10.42",
        "10.10.10.20",
    }

    assert len(services) == 1

    service = services[0]

    assert service.host_ip == "10.10.10.20"
    assert service.port == 80
    assert service.protocol == "tcp"


def test_entity_tracker_merges_repeated_service_observations():
    first_seen = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    second_seen = first_seen + timedelta(seconds=10)

    flow_one = make_flow(
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.20",
        destination_port=80,
        timestamp=first_seen,
    )

    flow_two = make_flow(
        source_ip="10.10.10.42",
        source_port=49153,
        destination_ip="10.10.10.20",
        destination_port=80,
        timestamp=second_seen,
    )

    tracker = EntityTracker()

    tracker.add_flow(flow_one)
    tracker.add_flow(flow_two)

    hosts = tracker.hosts()
    services = tracker.services()

    assert len(hosts) == 2
    assert len(services) == 1

    service = services[0]

    assert service.host_ip == "10.10.10.20"
    assert service.port == 80
    assert service.first_seen == first_seen
    assert service.last_seen == second_seen


def test_entity_tracker_handles_reverse_traffic():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    flow = make_flow(
        source_ip="10.10.10.20",
        source_port=80,
        destination_ip="10.10.10.42",
        destination_port=49152,
        timestamp=timestamp,
    )

    tracker = EntityTracker()

    tracker.add_flow(flow)

    services = tracker.services()

    assert len(services) == 1

    service = services[0]

    assert service.host_ip == "10.10.10.42"
    assert service.port == 49152


def test_entity_tracker_ignores_portless_responder():
    timestamp = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    flow = Flow(
        endpoint_a=Endpoint(
            ip="10.10.10.20",
            port=None,
        ),
        endpoint_b=Endpoint(
            ip="10.10.10.42",
            port=49152,
        ),
        protocol="1",
        first_seen=timestamp,
        last_seen=timestamp,
        initiator=Endpoint(
            ip="10.10.10.20",
            port=None,
        ),
        responder=Endpoint(
            ip="10.10.10.42",
            port=49152,
        ),
    )

    tracker = EntityTracker()

    tracker.add_flow(flow)

    assert len(tracker.hosts()) == 2
    assert len(tracker.services()) == 1


def test_entity_tracker_discovers_hostnames():
    from datetime import datetime, timezone

    from wiretap.capture.entities import EntityTracker
    from wiretap.models import (
        DNSAnswer,
        DNSQuery,
        DNSTransaction,
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

    tracker = EntityTracker()

    tracker.add_dns_transaction(transaction)

    hostnames = tracker.hostnames()

    assert len(hostnames) == 1

    hostname = hostnames[0]

    assert hostname.name == "fileserver.corp.local"
    assert hostname.first_seen == timestamp
    assert hostname.last_seen == timestamp


def test_dns_transaction_discovers_resolved_host():
    from datetime import datetime, timezone

    from wiretap.capture.entities import EntityTracker
    from wiretap.models import (
        DNSAnswer,
        DNSQuery,
        DNSTransaction,
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

    tracker = EntityTracker()

    tracker.add_dns_transaction(transaction)

    hosts = tracker.hosts()

    assert {
        host.ip
        for host in hosts
    } == {
        "10.10.10.20",
    }