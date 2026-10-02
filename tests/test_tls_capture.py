from wiretap.capture.processor import CaptureProcessor
from wiretap.models import (
    TLSClientHello,
    TLSServerHello,
)


def test_tls_packets_produce_tls_observations(
    tls_packets,
):
    processor = CaptureProcessor()

    for packet in tls_packets:
        processor.process_packet(packet)

    client_hellos = [
        observation
        for observation in processor.observations
        if isinstance(
            observation,
            TLSClientHello,
        )
    ]

    server_hellos = [
        observation
        for observation in processor.observations
        if isinstance(
            observation,
            TLSServerHello,
        )
    ]

    assert len(client_hellos) == 1
    assert len(server_hellos) == 1

    client = client_hellos[0]
    server = server_hellos[0]

    assert client.source_ip == "10.10.10.42"
    assert client.destination_ip == "10.10.10.20"
    assert client.destination_port == 443

    assert server.source_ip == "10.10.10.20"
    assert server.destination_ip == "10.10.10.42"
    assert server.source_port == 443


def test_tls_packets_are_correlated(
    tls_packets,
):
    processor = CaptureProcessor()

    for packet in tls_packets:
        processor.process_packet(packet)

    transactions = (
        processor.tls_tracker.transactions()
    )

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.client_hello is not None
    assert transaction.server_hello is not None

    assert (
        transaction.client_hello.source_ip
        == "10.10.10.42"
    )

    assert (
        transaction.server_hello.source_ip
        == "10.10.10.20"
    )


def test_tls_packets_create_flow(
    tls_packets,
):
    processor = CaptureProcessor()

    for packet in tls_packets:
        processor.process_packet(packet)

    flows = processor.flow_tracker.flows()

    matching = [
        flow
        for flow in flows
        if {
            flow.endpoint_a.ip,
            flow.endpoint_b.ip,
        }
        == {
            "10.10.10.42",
            "10.10.10.20",
        }
        and flow.protocol == "tcp"
    ]

    assert len(matching) == 1

    flow = matching[0]

    assert flow.initiator is not None
    assert flow.responder is not None

    assert flow.initiator.ip == "10.10.10.42"
    assert flow.responder.ip == "10.10.10.20"