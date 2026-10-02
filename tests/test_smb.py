from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from wiretap.capture.smb import smb_observations_from_packet
from wiretap.models import (
    SMBFileOperation,
    SMBNegotiate,
    SMBSessionSetup,
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


def test_non_smb_packet_returns_no_observations():
    packet = make_packet(
        b"not smb",
    )

    assert smb_observations_from_packet(packet) == []


def test_smb2_negotiate_request():
    header = smb2_header(
        command=0x0000,
        message_id=1,
    )

    body = bytearray(36)

    body[0:2] = (36).to_bytes(
        2,
        "little",
    )

    body[2:4] = (3).to_bytes(
        2,
        "little",
    )

    body += (0x0202).to_bytes(
        2,
        "little",
    )

    body += (0x0210).to_bytes(
        2,
        "little",
    )

    body += (0x0311).to_bytes(
        2,
        "little",
    )

    observations = smb_observations_from_packet(
        make_packet(
            header + bytes(body),
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBNegotiate,
    )

    assert observation.version == "SMB3"
    assert observation.command == "NEGOTIATE"
    assert observation.message_type == "request"

    assert observation.dialects == [
        "SMB 2.0.2",
        "SMB 2.1",
        "SMB 3.1.1",
    ]


def test_smb2_negotiate_response():
    header = smb2_header(
        command=0x0000,
        message_id=1,
        flags=0x00000001,
    )

    body = bytearray(8)

    body[0:2] = (65).to_bytes(
        2,
        "little",
    )

    body[4:6] = (0x0311).to_bytes(
        2,
        "little",
    )

    observations = smb_observations_from_packet(
        make_packet(
            header + bytes(body),
            source="10.10.10.30",
            destination="10.10.10.42",
            sport=445,
            dport=49153,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBNegotiate,
    )

    assert observation.message_type == "response"
    assert observation.dialect == "SMB 3.1.1"


def test_smb2_tree_connect_extracts_share():
    share = r"\\10.10.10.30\ADMIN$"

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

    observations = smb_observations_from_packet(
        make_packet(
            header + bytes(body) + path,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBTreeConnect,
    )

    assert observation.share == share
    assert observation.session_id == 123
    assert observation.tree_id == 456


def test_smb2_create_request_extracts_path():
    path = r"\Temp\payload.exe"

    header = smb2_header(
        command=0x0005,
        message_id=10,
    )

    encoded_path = path.encode(
        "utf-16-le"
    )

    body = (
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
        + len(encoded_path).to_bytes(2, "little")
        + b"\x00" * 8
        + encoded_path
    )

    observations = smb_observations_from_packet(
        make_packet(
            header + body,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBFileOperation,
    )

    assert observation.operation == "CREATE"
    assert observation.path == path
    assert observation.file_id is None


def test_smb2_create_response_extracts_file_id():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    header = smb2_header(
        command=0x0005,
        message_id=10,
        flags=0x00000001,
    )

    body = (
        b"\x00" * 64
        + file_id
    )

    observations = smb_observations_from_packet(
        make_packet(
            header + body,
            source="10.10.10.30",
            destination="10.10.10.42",
            sport=445,
            dport=49153,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBFileOperation,
    )

    assert observation.operation == "CREATE"

    assert observation.file_id == (
        "00112233445566778899aabbccddeeff"
    )

    assert observation.path is None


def test_smb2_read_request_extracts_file_id_length_and_offset():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    length = 4096
    offset = 8192

    header = smb2_header(
        command=0x0008,
        message_id=11,
        session_id=123,
        tree_id=456,
    )

    body = (
        b"\x00" * 4
        + length.to_bytes(
            4,
            "little",
        )
        + offset.to_bytes(
            8,
            "little",
        )
        + file_id
    )

    observations = smb_observations_from_packet(
        make_packet(
            header + body,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBFileOperation,
    )

    assert observation.operation == "READ"

    assert observation.file_id == (
        "00112233445566778899aabbccddeeff"
    )

    assert observation.length == 4096
    assert observation.offset == 8192


def test_smb2_write_request_extracts_file_id_length_and_offset():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    length = 2048
    offset = 16384

    header = smb2_header(
        command=0x0009,
        message_id=12,
        session_id=123,
        tree_id=456,
    )

    body = (
        b"\x00" * 4
        + length.to_bytes(
            4,
            "little",
        )
        + offset.to_bytes(
            8,
            "little",
        )
        + file_id
    )

    observations = smb_observations_from_packet(
        make_packet(
            header + body,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBFileOperation,
    )

    assert observation.operation == "WRITE"

    assert observation.file_id == (
        "00112233445566778899aabbccddeeff"
    )

    assert observation.length == 2048
    assert observation.offset == 16384


def test_smb2_close_request_extracts_file_id():
    file_id = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    header = smb2_header(
        command=0x0006,
        message_id=13,
        session_id=123,
        tree_id=456,
    )

    body = (
        b"\x00" * 16
        + file_id
    )

    observations = smb_observations_from_packet(
        make_packet(
            header + body,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBFileOperation,
    )

    assert observation.operation == "CLOSE"

    assert observation.file_id == (
        "00112233445566778899aabbccddeeff"
    )


def test_smb2_session_setup_returns_session_observation():
    header = smb2_header(
        command=0x0001,
        message_id=20,
        session_id=123,
    )

    body = b"\x00" * 24

    observations = smb_observations_from_packet(
        make_packet(
            header + body,
        )
    )

    assert len(observations) == 1

    observation = observations[0]

    assert isinstance(
        observation,
        SMBSessionSetup,
    )

    assert observation.command == "SESSION_SETUP"
    assert observation.message_type == "request"