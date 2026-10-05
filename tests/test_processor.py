from datetime import datetime, timezone

from wiretap.capture.processor import CaptureProcessor
from wiretap.capture.reader import PcapReader
from wiretap.models import EntityRef, SMBFileOperation


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
            EntityRef(
                type="host",
                value="10.10.10.42",
            ),
            "connects_to",
            EntityRef(
                type="host",
                value="10.10.10.20",
            ),
        ),
        (
            EntityRef(
                type="host",
                value="10.10.10.42",
            ),
            "connects_to",
            EntityRef(
                type="host",
                value="10.10.10.30",
            ),
        ),
        (
            EntityRef(
                type="host",
                value="10.10.10.42",
            ),
            "connects_to",
            EntityRef(
                type="host",
                value="10.10.10.10",
            ),
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
            EntityRef(
                type="host",
                value="10.10.10.42",
            ),
            "queried",
            EntityRef(
                type="hostname",
                value="fileserver.corp.local",
            ),
        ),
        (
            EntityRef(
                type="hostname",
                value="fileserver.corp.local",
            ),
            "resolves_to",
            EntityRef(
                type="host",
                value="10.10.10.20",
            ),
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


def test_capture_processor_resolves_smb_file_relationships():
    timestamp = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    processor = CaptureProcessor()

    file_id = "aa" * 16
    path = r"\share\payload.exe"

    create_request = SMBFileOperation(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="CREATE",
        message_type="request",
        message_id=1,
        operation="CREATE",
        path=path,
    )

    create_response = SMBFileOperation(
        timestamp=timestamp,
        source_ip="10.10.10.30",
        source_port=445,
        destination_ip="10.10.10.42",
        destination_port=49152,
        version="SMB3",
        command="CREATE",
        message_type="response",
        message_id=1,
        operation="CREATE",
        file_id=file_id,
    )

    write = SMBFileOperation(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="WRITE",
        message_type="request",
        message_id=2,
        operation="WRITE",
        file_id=file_id,
    )

    close = SMBFileOperation(
        timestamp=timestamp,
        source_ip="10.10.10.42",
        source_port=49152,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="CLOSE",
        message_type="request",
        message_id=3,
        operation="CLOSE",
        file_id=file_id,
    )

    processor.observations.extend(
        [
            create_request,
            create_response,
            write,
            close,
        ]
    )

    processor.smb_tracker.add(
        create_request
    )

    processor.smb_tracker.add(
        create_response
    )

    processor.smb_tracker.add(
        write
    )

    processor.smb_tracker.add(
        close
    )

    processor.finalize()

    relationships = {
        (
            relationship.source,
            relationship.relation,
            relationship.target,
        )
        for relationship
        in processor.relationship_tracker.relationships()
    }

    host = EntityRef(
        type="host",
        value="10.10.10.42",
    )

    target = EntityRef(
        type="path",
        value=path,
    )

    assert (
        host,
        "created_path",
        target,
    ) in relationships

    assert (
        host,
        "writes_to",
        target,
    ) in relationships

    assert (
        host,
        "closed_path",
        target,
    ) in relationships

    assert write.resolved_path == path
    assert close.resolved_path == path