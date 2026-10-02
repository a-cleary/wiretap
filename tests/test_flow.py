from datetime import datetime, timedelta, timezone

from wiretap.capture import FlowTracker
from wiretap.models import Connection, Endpoint


def test_tcp_flow_identifies_initiator():
    tracker = FlowTracker()

    start = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    )

    client = Endpoint("10.10.10.42", 49152)
    server = Endpoint("10.10.10.20", 80)

    # SYN: client -> server
    tracker.add(
        Connection(
            source=client,
            destination=server,
            protocol="tcp",
            first_seen=start,
            last_seen=start,
            packets=1,
            bytes=60,
            tcp_flags=0x02,
        )
    )

    # SYN-ACK: server -> client
    tracker.add(
        Connection(
            source=server,
            destination=client,
            protocol="tcp",
            first_seen=start + timedelta(seconds=1),
            last_seen=start + timedelta(seconds=1),
            packets=1,
            bytes=60,
            tcp_flags=0x12,
        )
    )

    # ACK: client -> server
    tracker.add(
        Connection(
            source=client,
            destination=server,
            protocol="tcp",
            first_seen=start + timedelta(seconds=2),
            last_seen=start + timedelta(seconds=2),
            packets=1,
            bytes=54,
            tcp_flags=0x10,
        )
    )

    flows = tracker.flows()

    assert len(flows) == 1

    flow = flows[0]

    assert flow.initiator == client
    assert flow.responder == server

    assert flow.packets == 3
    assert flow.bytes == 174