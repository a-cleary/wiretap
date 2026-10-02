import hashlib
from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import IP, TCP

from wiretap.capture.connections import packet_timestamp
from wiretap.models import TLSCertificate


def _decode(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return str(value)


def _datetime(value: Any) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value

    return None


def _fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _certificate_bytes(
    certificate: Any,
) -> bytes | None:
    for attribute in (
        "cert",
        "certificate",
        "der",
        "data",
    ):
        value = getattr(
            certificate,
            attribute,
            None,
        )

        if isinstance(value, bytes):
            return value

    return None


def _subject(
    certificate: Any,
) -> str | None:
    for attribute in (
        "subject",
        "subject_name",
        "tbsCertificate",
    ):
        value = getattr(
            certificate,
            attribute,
            None,
        )

        if value is None:
            continue

        if isinstance(value, str):
            return value

        decoded = _decode(value)

        if decoded:
            return decoded

    return None


def _issuer(
    certificate: Any,
) -> str | None:
    for attribute in (
        "issuer",
        "issuer_name",
    ):
        value = getattr(
            certificate,
            attribute,
            None,
        )

        if value is None:
            continue

        if isinstance(value, str):
            return value

        decoded = _decode(value)

        if decoded:
            return decoded

    return None


def _serial_number(
    certificate: Any,
) -> str | None:
    value = getattr(
        certificate,
        "serial",
        None,
    )

    if value is None:
        value = getattr(
            certificate,
            "serialNumber",
            None,
        )

    if value is None:
        return None

    if isinstance(value, int):
        return str(value)

    return _decode(value)


def _validity(
    certificate: Any,
) -> tuple[
    datetime | None,
    datetime | None,
]:
    not_before = getattr(
        certificate,
        "notBefore",
        None,
    )

    if not_before is None:
        not_before = getattr(
            certificate,
            "not_before",
            None,
        )

    not_after = getattr(
        certificate,
        "notAfter",
        None,
    )

    if not_after is None:
        not_after = getattr(
            certificate,
            "not_after",
            None,
        )

    return (
        _datetime(not_before),
        _datetime(not_after),
    )


def _subject_alt_names(
    certificate: Any,
) -> list[str]:
    names: list[str] = []

    extensions = getattr(
        certificate,
        "extensions",
        None,
    )

    if extensions is None:
        return names

    try:
        extensions = list(extensions)
    except TypeError:
        extensions = [extensions]

    for extension in extensions:
        extension_name = type(
            extension
        ).__name__.lower()

        if (
            "subjectaltname" not in extension_name
            and "subject_alt_name"
            not in extension_name
        ):
            continue

        values = getattr(
            extension,
            "general_names",
            None,
        )

        if values is None:
            values = getattr(
                extension,
                "names",
                None,
            )

        if values is None:
            values = getattr(
                extension,
                "generalName",
                None,
            )

        if values is None:
            continue

        if not isinstance(values, list):
            try:
                values = list(values)
            except TypeError:
                values = [values]

        for value in values:
            for attribute in (
                "dNSName",
                "dnsName",
                "ipAddress",
                "uniformResourceIdentifier",
                "uri",
            ):
                candidate = getattr(
                    value,
                    attribute,
                    None,
                )

                decoded = _decode(candidate)

                if decoded:
                    names.append(decoded)
                    break

    return names


def _extract_certificates(
    packet: Any,
) -> list[Any]:
    try:
        from scapy.layers.tls.handshake import (
            TLSCertificate as ScapyTLSCertificate,
        )
    except ImportError:
        return []

    if not packet.haslayer(
        ScapyTLSCertificate
    ):
        return []

    handshake = packet[
        ScapyTLSCertificate
    ]

    certificates = getattr(
        handshake,
        "certs",
        None,
    )

    if certificates is None:
        certificates = getattr(
            handshake,
            "certificate_list",
            None,
        )

    if certificates is None:
        return []

    if not isinstance(certificates, list):
        try:
            certificates = list(certificates)
        except TypeError:
            certificates = [certificates]

    return certificates


def tls_certificates_from_packet(
    packet: Any,
) -> list[TLSCertificate]:
    if not packet.haslayer(IP):
        return []

    if not packet.haslayer(TCP):
        return []

    certificates = _extract_certificates(
        packet
    )

    if not certificates:
        return []

    ip = packet[IP]
    tcp = packet[TCP]
    timestamp = packet_timestamp(packet)

    results: list[TLSCertificate] = []

    for certificate in certificates:
        data = _certificate_bytes(
            certificate
        )

        if data is None:
            continue

        not_before, not_after = _validity(
            certificate
        )

        results.append(
            TLSCertificate(
                timestamp=timestamp,
                source_ip=ip.src,
                source_port=int(tcp.sport),
                destination_ip=ip.dst,
                destination_port=int(tcp.dport),
                fingerprint_sha256=_fingerprint(
                    data
                ),
                subject=_subject(
                    certificate
                ),
                issuer=_issuer(
                    certificate
                ),
                serial_number=_serial_number(
                    certificate
                ),
                not_before=not_before,
                not_after=not_after,
                subject_alt_names=(
                    _subject_alt_names(
                        certificate
                    )
                ),
            )
        )

    return results