from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from wiretap.capture.processor import CaptureProcessor
from wiretap.models import (
    EntityRef,
    Relationship,
    SMBTreeConnect,
)


def smb2_header(
    *,
    command: int,
    message_id: int,
    flags: int = 0,
    tree_id: int = 0,
    session_id: int = 0,
) -> bytes:
    header = bytearray(64)

    header[0:4] = b"\xfeSMB"

    header[4:6] = (64).to_bytes(
        2,
        "little",
    )

    header[12:14] = command.to_bytes(
        2,
        "little",
    )

    header[16:20] = flags.to_bytes(
        4,
        "little",
    )

    header[24:32] = message_id.to_bytes(
        8,
        "little",
    )

    header[36:40] = tree_id.to_bytes(
        4,
        "little",
    )

    header[40:48] = session_id.to_bytes(
        8,
        "little",
    )

    return bytes(header)


def netbios(payload: bytes) -> bytes:
    return (
        b"\x00"
        + len(payload).to_bytes(3, "big")
        + payload
    )


def make_packet(
    payload: bytes,
    *,
    source="10.10.10.42",
    destination="10.10.10.30",
    sport=49153,
    dport=445,
):
    packet = (
        IP(
            src=source,
            dst=destination,
        )
        / TCP(
            sport=sport,
            dport=dport,
        )
        / Raw(
            load=netbios(payload),
        )
    )

    packet.time = 1767268801.0

    return packet


def make_tree_connect(
    share=r"\\10.10.10.30\ADMIN$",
):
    header = smb2_header(
        command=0x0003,
        message_id=2,
        session_id=123,
        tree_id=456,
    )

    path = share.encode(
        "utf-16-le"
    )

    body = bytearray(8)

    body[0:2] = (9).to_bytes(
        2,
        "little",
    )

    path_offset = 64 + 8

    body[4:6] = path_offset.to_bytes(
        2,
        "little",
    )

    body[6:8] = len(path).to_bytes(
        2,
        "little",
    )

    return header + bytes(body) + path


def make_create():
    header = smb2_header(
        command=0x0005,
        message_id=3,
        session_id=123,
        tree_id=456,
    )

    return header + b"\x00" * 32


def test_processor_collects_smb_observations():
    processor = CaptureProcessor()

    packet = make_packet(
        make_tree_connect()
    )

    processor.process_packet(packet)

    observations = processor.observations

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBTreeConnect,
    )

    assert observation.share == (
        r"\\10.10.10.30\ADMIN$"
    )


def test_processor_creates_smb_share_entity():
    processor = CaptureProcessor()

    packet = make_packet(
        make_tree_connect()
    )

    processor.process_packet(packet)

    share = EntityRef(
        type="share",
        value=r"\\10.10.10.30\ADMIN$",
    )

    assert share in processor.entity_tracker.refs()


def test_processor_creates_accessed_share_relationship():
    processor = CaptureProcessor()

    packet = make_packet(
        make_tree_connect()
    )

    processor.process_packet(packet)

    expected = Relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.42",
        ),
        relation="accessed_share",
        target=EntityRef(
            type="share",
            value=r"\\10.10.10.30\ADMIN$",
        ),
        first_seen=datetime.fromtimestamp(
            1767268801.0,
            tz=timezone.utc,
        ),
        last_seen=datetime.fromtimestamp(
            1767268801.0,
            tz=timezone.utc,
        ),
    )

    assert expected in (
        processor.relationship_tracker.relationships()
    )


def test_processor_tracks_smb_transaction():
    processor = CaptureProcessor()

    request = make_packet(
        make_tree_connect(),
    )

    response = make_packet(
        smb2_header(
            command=0x0003,
            message_id=2,
            flags=0x00000001,
            tree_id=456,
            session_id=123,
        )
        + b"\x00" * 8,
        source="10.10.10.30",
        destination="10.10.10.42",
        sport=445,
        dport=49153,
    )

    processor.process_packet(request)
    processor.process_packet(response)

    transactions = (
        processor.smb_tracker.transactions()
    )

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.request is not None
    assert transaction.response is not None

    assert transaction.request.message_id == 2
    assert transaction.response.message_id == 2


def test_processor_still_creates_tcp_flow_for_smb():
    processor = CaptureProcessor()

    packet = make_packet(
        make_tree_connect()
    )

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
            "10.10.10.30",
        }
        and flow.protocol == "tcp"
    ]

    assert len(matching) == 1

    flow = matching[0]

    assert flow.endpoint_a.port in {
        445,
        49153,
    }

    assert flow.endpoint_b.port in {
        445,
        49153,
    }


def test_processor_tracks_smb_file_handle():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    path = r"\Temp\payload.exe".encode(
        "utf-16-le"
    )

    request_header = smb2_header(
        command=0x0005,
        message_id=10,
    )

    request_body = (
        b"\x39\x00"
        + b"\x00"
        + b"\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + (120).to_bytes(2, "little")
        + len(path).to_bytes(2, "little")
        + b"\x00" * 8
        + path
    )

    response_header = smb2_header(
        command=0x0005,
        message_id=10,
        flags=0x00000001,
    )

    response_body = (
        b"\x00" * 64
        + file_id
    )

    processor = CaptureProcessor()

    processor.process_packet(
        make_packet(
            request_header + request_body
        )
    )

    processor.process_packet(
        make_packet(
            response_header + response_body,
            source="10.10.10.30",
            destination="10.10.10.42",
            sport=445,
            dport=49153,
        )
    )

    processor.finalize()

    assert processor.smb_file_tracker.resolve(
        "00112233445566778899aabbccddeeff"
    ) == r"\Temp\payload.exe"


def test_processor_resolves_smb_file_operation_path():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    path = r"\Temp\payload.exe".encode(
        "utf-16-le"
    )

    create_request_header = smb2_header(
        command=0x0005,
        message_id=10,
    )

    create_request_body = (
        b"\x39\x00"
        + b"\x00"
        + b"\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + (120).to_bytes(2, "little")
        + len(path).to_bytes(2, "little")
        + b"\x00" * 8
        + path
    )

    create_response_header = smb2_header(
        command=0x0005,
        message_id=10,
        flags=0x00000001,
    )

    create_response_body = (
        b"\x00" * 64
        + file_id
    )

    read_header = smb2_header(
        command=0x0008,
        message_id=11,
        session_id=123,
        tree_id=456,
    )

    read_length = 4096
    read_offset = 8192

    read_body = (
        b"\x00" * 4
        + read_length.to_bytes(
            4,
            "little",
        )
        + read_offset.to_bytes(
            8,
            "little",
        )
        + file_id
    )

    processor = CaptureProcessor()

    processor.process_packet(
        make_packet(
            create_request_header
            + create_request_body
        )
    )

    processor.process_packet(
        make_packet(
            create_response_header
            + create_response_body,
            source="10.10.10.30",
            destination="10.10.10.42",
            sport=445,
            dport=49153,
        )
    )

    processor.process_packet(
        make_packet(
            read_header + read_body,
        )
    )

    processor.finalize()

    read_operations = [
        observation
        for observation in processor.observations
        if (
            getattr(
                observation,
                "operation",
                None,
            )
            == "READ"
        )
    ]

    assert len(read_operations) == 1

    assert read_operations[0].file_id == (
        "00112233445566778899aabbccddeeff"
    )

    assert read_operations[0].resolved_path == (
        r"\Temp\payload.exe"
    )

    assert read_operations[0].length == 4096
    assert read_operations[0].offset == 8192


def test_processor_resolves_smb_write_path():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    path = r"\Temp\payload.exe".encode(
        "utf-16-le"
    )

    create_request_header = smb2_header(
        command=0x0005,
        message_id=10,
    )

    create_request_body = (
        b"\x39\x00"
        + b"\x00"
        + b"\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + (120).to_bytes(2, "little")
        + len(path).to_bytes(2, "little")
        + b"\x00" * 8
        + path
    )

    create_response_header = smb2_header(
        command=0x0005,
        message_id=10,
        flags=0x00000001,
    )

    create_response_body = (
        b"\x00" * 64
        + file_id
    )

    write_header = smb2_header(
        command=0x0009,
        message_id=11,
        session_id=123,
        tree_id=456,
    )

    write_length = 2048
    write_offset = 16384

    write_body = (
        b"\x00" * 4
        + write_length.to_bytes(
            4,
            "little",
        )
        + write_offset.to_bytes(
            8,
            "little",
        )
        + file_id
    )

    processor = CaptureProcessor()

    processor.process_packet(
        make_packet(
            create_request_header
            + create_request_body
        )
    )

    processor.process_packet(
        make_packet(
            create_response_header
            + create_response_body,
            source="10.10.10.30",
            destination="10.10.10.42",
            sport=445,
            dport=49153,
        )
    )

    processor.process_packet(
        make_packet(
            write_header + write_body,
        )
    )

    processor.finalize()

    write_operations = [
        observation
        for observation in processor.observations
        if (
            getattr(
                observation,
                "operation",
                None,
            )
            == "WRITE"
        )
    ]

    assert len(write_operations) == 1

    assert write_operations[0].file_id == (
        "00112233445566778899aabbccddeeff"
    )

    assert write_operations[0].resolved_path == (
        r"\Temp\payload.exe"
    )

    assert write_operations[0].length == 2048
    assert write_operations[0].offset == 16384


def test_processor_resolves_smb_close_path():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    path = r"\Temp\payload.exe".encode(
        "utf-16-le"
    )

    create_request_header = smb2_header(
        command=0x0005,
        message_id=10,
    )

    create_request_body = (
        b"\x39\x00"
        + b"\x00"
        + b"\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 4
        + (120).to_bytes(2, "little")
        + len(path).to_bytes(2, "little")
        + b"\x00" * 8
        + path
    )

    create_response_header = smb2_header(
        command=0x0005,
        message_id=10,
        flags=0x00000001,
    )

    create_response_body = (
        b"\x00" * 64
        + file_id
    )

    close_header = smb2_header(
        command=0x0006,
        message_id=30,
        session_id=123,
        tree_id=456,
    )

    close_body = (
        b"\x00" * 16
        + file_id
    )

    processor = CaptureProcessor()

    processor.process_packet(
        make_packet(
            create_request_header
            + create_request_body
        )
    )

    processor.process_packet(
        make_packet(
            create_response_header
            + create_response_body,
            source="10.10.10.30",
            destination="10.10.10.42",
            sport=445,
            dport=49153,
        )
    )

    processor.process_packet(
        make_packet(
            close_header + close_body,
        )
    )

    processor.finalize()

    close_operations = [
        observation
        for observation in processor.observations
        if (
            getattr(
                observation,
                "operation",
                None,
            )
            == "CLOSE"
        )
    ]

    assert len(close_operations) == 1

    assert close_operations[0].file_id == (
        "00112233445566778899aabbccddeeff"
    )

    assert close_operations[0].resolved_path == (
        r"\Temp\payload.exe"
    )

    assert close_operations[0].length is None
    assert close_operations[0].offset is None