from typing import Any

from scapy.layers.inet import IP, TCP

from wiretap.capture.connections import packet_timestamp
from wiretap.models import TLSClientHello, TLSServerHello


def _decode(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return str(value)


def _tls_version(value: Any) -> str:
    if value is None:
        return "unknown"

    numeric_versions = {
        0x0300: "SSLv3",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }

    if isinstance(value, int):
        return numeric_versions.get(
            value,
            f"0x{value:04x}",
        )

    text = _decode(value)

    if text is None:
        return "unknown"

    return text


def _cipher_name(value: Any) -> str:
    if value is None:
        return "unknown"

    if isinstance(value, int):
        return f"0x{value:04x}"

    return _decode(value) or "unknown"


def _extract_extensions(handshake: Any) -> list[Any]:
    extensions = getattr(
        handshake,
        "ext",
        None,
    )

    if extensions is None:
        return []

    if isinstance(extensions, list):
        return extensions

    try:
        return list(extensions)
    except TypeError:
        return []


def _extract_server_name(handshake: Any) -> str | None:
    for extension in _extract_extensions(handshake):
        extension_name = type(extension).__name__.lower()

        if "servername" not in extension_name:
            continue

        servernames = getattr(
            extension,
            "servernames",
            None,
        )

        if servernames is None:
            servernames = getattr(
                extension,
                "server_name",
                None,
            )

        if servernames is None:
            continue

        if not isinstance(servernames, list):
            servernames = [servernames]

        for servername in servernames:
            name = getattr(
                servername,
                "servername",
                None,
            )

            if name is None:
                name = getattr(
                    servername,
                    "name",
                    None,
                )

            decoded = _decode(name)

            if decoded:
                return decoded

    return None


def _extract_alpn(handshake: Any) -> list[str]:
    protocols: list[str] = []

    for extension in _extract_extensions(handshake):
        extension_name = type(extension).__name__.lower()

        if "alpn" not in extension_name:
            continue

        values = getattr(
            extension,
            "protocols",
            None,
        )

        if values is None:
            values = getattr(
                extension,
                "protocol_name_list",
                None,
            )

        if values is None:
            continue

        if not isinstance(values, list):
            values = [values]

        for value in values:
            decoded = _decode(value)

            if decoded:
                protocols.append(decoded)

    return protocols


def _extract_cipher_suites(handshake: Any) -> list[str]:
    values = getattr(
        handshake,
        "ciphers",
        None,
    )

    if values is None:
        return []

    if not isinstance(values, list):
        try:
            values = list(values)
        except TypeError:
            values = [values]

    return [
        _cipher_name(value)
        for value in values
    ]


def _extract_selected_cipher(handshake: Any) -> str | None:
    value = getattr(
        handshake,
        "cipher",
        None,
    )

    if value is None:
        value = getattr(
            handshake,
            "cipher_suite",
            None,
        )

    if value is None:
        return None

    return _cipher_name(value)


def _extract_selected_alpn(handshake: Any) -> str | None:
    protocols = _extract_alpn(handshake)

    if not protocols:
        return None

    return protocols[0]


def tls_client_hello_from_packet(
    packet: Any,
) -> TLSClientHello | None:
    if not packet.haslayer(IP):
        return None

    if not packet.haslayer(TCP):
        return None

    try:
        from scapy.layers.tls.handshake import (
            TLSClientHello as ScapyTLSClientHello,
        )
    except ImportError:
        return None

    if not packet.haslayer(ScapyTLSClientHello):
        return None

    handshake = packet[ScapyTLSClientHello]
    ip = packet[IP]
    tcp = packet[TCP]

    return TLSClientHello(
        timestamp=packet_timestamp(packet),
        source_ip=ip.src,
        source_port=int(tcp.sport),
        destination_ip=ip.dst,
        destination_port=int(tcp.dport),
        version=_tls_version(
            getattr(handshake, "version", None)
        ),
        server_name=_extract_server_name(
            handshake
        ),
        alpn_protocols=_extract_alpn(
            handshake
        ),
        cipher_suites=_extract_cipher_suites(
            handshake
        ),
    )


def tls_server_hello_from_packet(
    packet: Any,
) -> TLSServerHello | None:
    if not packet.haslayer(IP):
        return None

    if not packet.haslayer(TCP):
        return None

    try:
        from scapy.layers.tls.handshake import (
            TLSServerHello as ScapyTLSServerHello,
        )
    except ImportError:
        return None

    if not packet.haslayer(ScapyTLSServerHello):
        return None

    handshake = packet[ScapyTLSServerHello]
    ip = packet[IP]
    tcp = packet[TCP]

    return TLSServerHello(
        timestamp=packet_timestamp(packet),
        source_ip=ip.src,
        source_port=int(tcp.sport),
        destination_ip=ip.dst,
        destination_port=int(tcp.dport),
        version=_tls_version(
            getattr(handshake, "version", None)
        ),
        cipher_suite=_extract_selected_cipher(
            handshake
        ),
        alpn_protocol=_extract_selected_alpn(
            handshake
        ),
    )