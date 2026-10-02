from typing import Any

from scapy.layers.inet import IP, TCP

from wiretap.capture.connections import packet_timestamp
from wiretap.models import (
    SMBFileOperation,
    SMBNegotiate,
    SMBObservation,
    SMBSessionSetup,
    SMBTreeConnect,
)


SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"


SMB2_COMMANDS = {
    0x0000: "NEGOTIATE",
    0x0001: "SESSION_SETUP",
    0x0002: "LOGOFF",
    0x0003: "TREE_CONNECT",
    0x0004: "TREE_DISCONNECT",
    0x0005: "CREATE",
    0x0006: "CLOSE",
    0x0008: "READ",
    0x0009: "WRITE",
    0x000a: "LOCK",
    0x000b: "IOCTL",
    0x000c: "CANCEL",
    0x000d: "ECHO",
    0x0010: "QUERY_DIRECTORY",
    0x0011: "CHANGE_NOTIFY",
    0x0012: "QUERY_INFO",
    0x0013: "SET_INFO",
}


SMB1_COMMANDS = {
    0x72: "NEGOTIATE",
    0x73: "SESSION_SETUP",
    0x75: "TREE_CONNECT",
    0xA2: "NT_CREATE_ANDX",
    0x2e: "READ_ANDX",
    0x2f: "WRITE_ANDX",
    0x04: "CLOSE",
}


def _payload_bytes(packet: Any) -> bytes | None:
    if not packet.haslayer(TCP):
        return None

    tcp = packet[TCP]

    payload = bytes(tcp.payload)

    if not payload:
        return None

    return payload


def _netbios_payload(data: bytes) -> bytes:
    """
    Strip an optional NetBIOS Session Service header.

    SMB over TCP commonly uses:

        00 <3-byte length> <SMB message>
    """

    if len(data) >= 4 and data[0] == 0x00:
        length = int.from_bytes(
            data[1:4],
            byteorder="big",
        )

        if length <= len(data) - 4:
            return data[4:4 + length]

    return data


def _decode_utf16(value: bytes) -> str | None:
    if not value:
        return None

    try:
        text = value.decode(
            "utf-16-le",
            errors="replace",
        ).rstrip("\x00")

        return text or None

    except UnicodeDecodeError:
        return None


def _decode_ascii(value: bytes) -> str | None:
    if not value:
        return None

    text = value.decode(
        "latin-1",
        errors="replace",
    ).rstrip("\x00")

    return text or None


def _timestamp(packet: Any):
    return packet_timestamp(packet)


def _base_observation(
    packet: Any,
    version: str,
    command: str,
    message_type: str,
    message_id: int | None = None,
    session_id: int | None = None,
    tree_id: int | None = None,
) -> SMBObservation:
    ip = packet[IP]
    tcp = packet[TCP]

    return SMBObservation(
        timestamp=_timestamp(packet),
        source_ip=ip.src,
        source_port=int(tcp.sport),
        destination_ip=ip.dst,
        destination_port=int(tcp.dport),
        version=version,
        command=command,
        message_type=message_type,
        message_id=message_id,
        session_id=session_id,
        tree_id=tree_id,
    )


def _parse_smb2(
    packet: Any,
    data: bytes,
) -> SMBObservation | None:
    if len(data) < 64:
        return None

    if data[:4] != SMB2_MAGIC:
        return None

    command_id = int.from_bytes(
        data[12:14],
        byteorder="little",
    )

    command = SMB2_COMMANDS.get(
        command_id,
        f"UNKNOWN_0x{command_id:04x}",
    )

    message_id = int.from_bytes(
        data[24:32],
        byteorder="little",
    )

    tree_id = int.from_bytes(
        data[36:40],
        byteorder="little",
    )

    session_id = int.from_bytes(
        data[40:48],
        byteorder="little",
    )

    flags = int.from_bytes(
        data[16:20],
        byteorder="little",
    )

    is_response = bool(
        flags & 0x00000001
    )

    message_type = (
        "response"
        if is_response
        else "request"
    )

    version = "SMB3"

    return _parse_smb2_command(
        packet=packet,
        data=data,
        version=version,
        command=command,
        message_type=message_type,
        message_id=message_id,
        session_id=session_id,
        tree_id=tree_id,
    )


def _parse_smb2_command(
    packet: Any,
    data: bytes,
    version: str,
    command: str,
    message_type: str,
    message_id: int,
    session_id: int,
    tree_id: int,
) -> SMBObservation:
    base = _base_observation(
        packet=packet,
        version=version,
        command=command,
        message_type=message_type,
        message_id=message_id,
        session_id=session_id,
        tree_id=tree_id,
    )

    if command == "NEGOTIATE":
        return _parse_negotiate(
            packet,
            data,
            base,
        )

    if command == "SESSION_SETUP":
        return _parse_session_setup(
            packet,
            data,
            base,
        )

    if command == "TREE_CONNECT":
        return _parse_tree_connect(
            packet,
            data,
            base,
        )

    if command == "CREATE":
        return _parse_create(
            data,
            base,
        )

    if command == "READ":
        return _parse_read(
            data,
            base,
        )

    if command == "WRITE":
        return _parse_write(
            data,
            base,
        )

    if command == "CLOSE":
        return _parse_close(
            data,
            base
        )

    if command in {
        "QUERY_DIRECTORY",
        "QUERY_INFO",
        "SET_INFO",
    }:
        return SMBFileOperation(
            **base.__dict__,
            operation=command,
        )

    return base


def _parse_create(
    data: bytes,
    base: SMBObservation,
) -> SMBFileOperation:
    path = None
    file_id = None

    if base.message_type == "request":
        path = _extract_create_path(data)

    elif base.message_type == "response":
        file_id = _extract_create_file_id(data)

    return SMBFileOperation(
        **base.__dict__,
        operation="CREATE",
        path=path,
        file_id=file_id,
    )


def _extract_create_path(
    data: bytes,
) -> str | None:
    """
    Extract the requested filename/path from an SMB2 CREATE request.

    SMB2 CREATE request fields begin at byte 64.

    NameOffset: 108:110
    NameLength: 110:112
    """

    if len(data) < 112:
        return None

    name_offset = int.from_bytes(
        data[108:110],
        byteorder="little",
    )

    name_length = int.from_bytes(
        data[110:112],
        byteorder="little",
    )

    if name_length == 0:
        return None

    end = name_offset + name_length

    if (
        name_offset < 64
        or end > len(data)
    ):
        return None

    return _decode_utf16(
        data[name_offset:end]
    )


def _extract_create_file_id(
    data: bytes,
) -> str | None:
    """
    Extract the 16-byte SMB2 CREATE response FileId.

    SMB2 CREATE response fields begin at byte 64.

    FileId: 128:144
    """

    if len(data) < 144:
        return None

    file_id = data[128:144]

    if len(file_id) != 16:
        return None

    return file_id.hex()


def _parse_read(
    data: bytes,
    base: SMBObservation,
) -> SMBFileOperation:
    """
    Extract the FileId, length, and offset from
    an SMB2 READ request.

    SMB2 READ request fields begin at byte 64.

    Length: 68:72
    Offset: 72:80
    FileId: 80:96
    """

    file_id = None
    offset = None
    length = None

    if base.message_type == "request":
        length = _extract_read_length(data)
        offset = _extract_read_offset(data)
        file_id = _extract_read_file_id(data)

    return SMBFileOperation(
        **base.__dict__,
        operation="READ",
        file_id=file_id,
        offset=offset,
        length=length,
    )

def _extract_read_length(
    data: bytes,
) -> int | None:
    if len(data) < 72:
        return None

    return int.from_bytes(
        data[68:72],
        byteorder="little",
    )


def _extract_read_offset(
    data: bytes,
) -> int | None:
    if len(data) < 80:
        return None

    return int.from_bytes(
        data[72:80],
        byteorder="little",
    )


def _extract_read_file_id(
    data: bytes,
) -> str | None:
    """
    Extract the 16-byte SMB2 READ request FileId.
    """

    if len(data) < 96:
        return None

    file_id = data[80:96]

    if len(file_id) != 16:
        return None

    return file_id.hex()


def _parse_negotiate(
    packet: Any,
    data: bytes,
    base: SMBObservation,
) -> SMBNegotiate:
    dialects: list[str] = []

    if base.message_type == "request":
        if len(data) < 66:
            return SMBNegotiate(
                **base.__dict__,
                dialects=dialects,
            )

        structure_size = int.from_bytes(
            data[64:66],
            byteorder="little",
        )

        if structure_size != 36:
            return SMBNegotiate(
                **base.__dict__,
                dialects=dialects,
            )

        dialect_count = int.from_bytes(
            data[66:68],
            byteorder="little",
        )

        offset = 64 + 36

        for index in range(dialect_count):
            start = offset + index * 2
            end = start + 2

            if end > len(data):
                break

            dialect_id = int.from_bytes(
                data[start:end],
                byteorder="little",
            )

            dialects.append(
                _smb2_dialect_name(
                    dialect_id
                )
            )

        return SMBNegotiate(
            **base.__dict__,
            dialects=dialects,
        )

    dialect = None

    if len(data) >= 72:
        dialect_id = int.from_bytes(
            data[68:70],
            byteorder="little",
        )

        dialect = _smb2_dialect_name(
            dialect_id
        )

    return SMBNegotiate(
        **base.__dict__,
        dialect=dialect,
        dialects=dialects,
    )


def _smb2_dialect_name(
    value: int,
) -> str:
    return {
        0x0202: "SMB 2.0.2",
        0x0210: "SMB 2.1",
        0x0300: "SMB 3.0",
        0x0302: "SMB 3.0.2",
        0x0311: "SMB 3.1.1",
    }.get(
        value,
        f"0x{value:04x}",
    )


def _parse_session_setup(
    packet: Any,
    data: bytes,
    base: SMBObservation,
) -> SMBSessionSetup:
    """
    Extract easily observable identity information.

    SMB2 Session Setup carries an authentication blob.
    NTLM identity information may be present inside that blob.
    """

    username = None
    domain = None
    workstation = None

    if len(data) >= 88:
        security_buffer_offset = int.from_bytes(
            data[68:70],
            byteorder="little",
        )

        security_buffer_length = int.from_bytes(
            data[70:72],
            byteorder="little",
        )

        start = security_buffer_offset
        end = start + security_buffer_length

        if (
            start >= 64
            and end <= len(data)
            and security_buffer_length > 0
        ):
            blob = data[start:end]

            (
                username,
                domain,
                workstation,
            ) = _extract_ntlm_identity(blob)

    return SMBSessionSetup(
        **base.__dict__,
        username=username,
        domain=domain,
        workstation=workstation,
    )


def _extract_ntlm_identity(
    blob: bytes,
) -> tuple[
    str | None,
    str | None,
    str | None,
]:
    """
    Best-effort extraction of NTLMv2 identity fields.

    We intentionally do not attempt authentication or
    credential recovery. This is passive capture parsing.
    """

    marker = b"NTLMSSP\x00"

    offset = blob.find(marker)

    if offset < 0:
        return None, None, None

    message = blob[offset:]

    if len(message) < 12:
        return None, None, None

    message_type = int.from_bytes(
        message[8:12],
        byteorder="little",
    )

    if message_type != 3:
        return None, None, None

    domain = _ntlm_field(
        message,
        28,
    )

    username = _ntlm_field(
        message,
        36,
    )

    workstation = _ntlm_field(
        message,
        44,
    )

    return username, domain, workstation


def _ntlm_field(
    message: bytes,
    offset: int,
) -> str | None:
    if len(message) < offset + 8:
        return None

    length = int.from_bytes(
        message[offset:offset + 2],
        byteorder="little",
    )

    buffer_offset = int.from_bytes(
        message[offset + 4:offset + 8],
        byteorder="little",
    )

    end = buffer_offset + length

    if (
        length == 0
        or buffer_offset >= len(message)
        or end > len(message)
    ):
        return None

    return _decode_utf16(
        message[buffer_offset:end]
    )


def _parse_tree_connect(
    packet: Any,
    data: bytes,
    base: SMBObservation,
) -> SMBTreeConnect:
    share = None

    if base.message_type == "request":
        share = _extract_tree_path(
            data
        )

    return SMBTreeConnect(
        **base.__dict__,
        share=share,
        share_type=None,
    )


def _extract_tree_path(
    data: bytes,
) -> str | None:
    """
    SMB2 TREE_CONNECT request:

    structure starts at byte 64.
    Path offset/length are at offsets 68/70.
    """

    if len(data) < 72:
        return None

    path_offset = int.from_bytes(
        data[68:70],
        byteorder="little",
    )

    path_length = int.from_bytes(
        data[70:72],
        byteorder="little",
    )

    end = path_offset + path_length

    if (
        path_offset < 64
        or path_length == 0
        or end > len(data)
    ):
        return None

    return _decode_utf16(
        data[path_offset:end]
    )


def _parse_smb1(
    packet: Any,
    data: bytes,
) -> SMBObservation | None:
    if len(data) < 32:
        return None

    if data[:4] != SMB1_MAGIC:
        return None

    command_id = data[4]

    command = SMB1_COMMANDS.get(
        command_id,
        f"UNKNOWN_0x{command_id:02x}",
    )

    flags = data[9]

    message_type = (
        "response"
        if flags & 0x80
        else "request"
    )

    base = _base_observation(
        packet=packet,
        version="SMB1",
        command=command,
        message_type=message_type,
    )

    return base


def smb_observations_from_packet(
    packet: Any,
) -> list[SMBObservation]:
    if not packet.haslayer(IP):
        return []

    if not packet.haslayer(TCP):
        return []

    tcp = packet[TCP]

    if (
        int(tcp.sport) != 445
        and int(tcp.dport) != 445
    ):
        return []

    payload = _payload_bytes(packet)

    if payload is None:
        return []

    data = _netbios_payload(payload)

    if data.startswith(SMB2_MAGIC):
        observation = _parse_smb2(
            packet,
            data,
        )

        return (
            [observation]
            if observation is not None
            else []
        )

    if data.startswith(SMB1_MAGIC):
        observation = _parse_smb1(
            packet,
            data,
        )

        return (
            [observation]
            if observation is not None
            else []
        )

    return []


def _parse_write(
    data: bytes,
    base: SMBObservation,
) -> SMBFileOperation:
    """
    Extract the FileId, length, and offset from
    an SMB2 WRITE request.

    SMB2 WRITE request fields begin at byte 64.

    Length: 68:72
    Offset: 72:80
    FileId: 80:96
    """

    file_id = None
    offset = None
    length = None

    if base.message_type == "request":
        length = _extract_write_length(data)
        offset = _extract_write_offset(data)
        file_id = _extract_write_file_id(data)

    return SMBFileOperation(
        **base.__dict__,
        operation="WRITE",
        file_id=file_id,
        offset=offset,
        length=length,
    )

def _extract_write_length(
    data: bytes,
) -> int | None:
    if len(data) < 72:
        return None

    return int.from_bytes(
        data[68:72],
        byteorder="little",
    )


def _extract_write_offset(
    data: bytes,
) -> int | None:
    if len(data) < 80:
        return None

    return int.from_bytes(
        data[72:80],
        byteorder="little",
    )


def _extract_write_file_id(
    data: bytes,
) -> str | None:
    """
    Extract the 16-byte SMB2 WRITE request FileId.
    """

    if len(data) < 96:
        return None

    file_id = data[80:96]

    if len(file_id) != 16:
        return None

    return file_id.hex()


def _parse_close(
    data: bytes,
    base: SMBObservation,
) -> SMBFileOperation:
    """
    Extract the FileId from an SMB2 CLOSE request.

    SMB2 CLOSE request fields begin at byte 64.

    FileId: 80:96
    """

    file_id = None

    if base.message_type == "request":
        file_id = _extract_close_file_id(
            data
        )

    return SMBFileOperation(
        **base.__dict__,
        operation="CLOSE",
        file_id=file_id,
    )


def _extract_close_file_id(
    data: bytes,
) -> str | None:
    """
    Extract the 16-byte SMB2 CLOSE request FileId.
    """

    if len(data) < 96:
        return None

    file_id = data[80:96]

    if len(file_id) != 16:
        return None

    return file_id.hex()