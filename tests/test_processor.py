from wiretap.capture import CaptureProcessor
from wiretap.capture.reader import PcapReader
from wiretap.models import DNSQuery


def test_capture_processor_collects_observations(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    dns_queries = [
        observation
        for observation in processor.observations
        if isinstance(observation, DNSQuery)
    ]

    assert len(dns_queries) == 1


def test_capture_processor_tracks_flows(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    flows = processor.flow_tracker.flows()

    assert len(flows) == 4


def test_capture_processor_tracks_http_transactions(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    transactions = (
        processor.http_tracker.transactions()
    )

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.request is not None
    assert transaction.response is not None


def test_capture_processor_tracks_dns_transactions(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    transactions = (
        processor.dns_tracker.transactions()
    )

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.query.query == "fileserver.corp.local"
    assert transaction.query.query_type == "A"
    assert transaction.query.transaction_id == 1234

    assert transaction.source_ip == "10.10.10.42"
    assert transaction.destination_ip == "10.10.10.10"

    assert transaction.response_code == 0

    assert len(transaction.answers) == 1

    answer = transaction.answers[0]

    assert answer.record_type == "A"
    assert answer.value == "10.10.10.20"
    assert answer.ttl == 300


def test_capture_processor_discovers_hosts(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    processor.finalize()

    hosts = processor.entity_tracker.hosts()

    assert {
        host.ip
        for host in hosts
    } == {
        "10.10.10.42",
        "10.10.10.20",
        "10.10.10.30",
        "10.10.10.10",
    }


def test_capture_processor_discovers_services(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    processor.finalize()

    services = processor.entity_tracker.services()

    assert {
        (
            service.host_ip,
            service.port,
            service.protocol,
        )
        for service in services
    } == {
        ("10.10.10.20", 80, "tcp"),
        ("10.10.10.30", 445, "tcp"),
        ("10.10.10.10", 88, "tcp"),
        ("10.10.10.10", 53, "udp"),
    }


def test_capture_processor_discovers_connections(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    processor.finalize()

    relationships = processor.relationship_tracker.relationships()

    connections = {
        (
            relationship.source,
            relationship.relation,
            relationship.target,
        )
        for relationship in relationships
        if relationship.relation == "connects_to"
    }

    assert connections == {
        (
            "10.10.10.42",
            "connects_to",
            "10.10.10.20",
        ),
        (
            "10.10.10.42",
            "connects_to",
            "10.10.10.30",
        ),
        (
            "10.10.10.42",
            "connects_to",
            "10.10.10.10",
        ),
    }


def test_capture_processor_discovers_dns_relationships(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    processor.finalize()

    relationships = processor.relationship_tracker.relationships()

    dns_relationships = {
        (
            relationship.source,
            relationship.relation,
            relationship.target,
        )
        for relationship in relationships
        if relationship.relation in {
            "queried",
            "resolves_to",
        }
    }

    assert dns_relationships == {
        (
            "10.10.10.42",
            "queried",
            "fileserver.corp.local",
        ),
        (
            "fileserver.corp.local",
            "resolves_to",
            "10.10.10.20",
        ),
    }


def test_capture_processor_discovers_hostnames(test_pcap):
    processor = CaptureProcessor()

    reader = PcapReader(test_pcap)

    for packet in reader.read():
        processor.process_packet(packet)

    processor.finalize()

    hostnames = processor.entity_tracker.hostnames()

    assert {
        hostname.name
        for hostname in hostnames
    } == {
        "fileserver.corp.local",
    }