from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP

from wiretap.capture.connections import packet_timestamp
from wiretap.models import DNSAnswer, DNSQuery


_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def _decode(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return str(value)


def _query_type(value: int) -> str:
    return _QTYPE_NAMES.get(
        value,
        str(value),
    )


def dns_query_from_packet(packet: Any) -> DNSQuery | None:
    if not packet.haslayer(IP):
        return None

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    if dns.qr != 0:
        return None

    if not dns.qd:
        return None

    if not packet.haslayer(DNSQR):
        return None

    ip = packet[IP]
    question = packet[DNSQR]

    query = _decode(question.qname)

    if query is None:
        return None

    return DNSQuery(
        timestamp=packet_timestamp(packet),
        source_ip=ip.src,
        destination_ip=ip.dst,
        query=query.rstrip("."),
        query_type=_query_type(int(question.qtype)),
        transaction_id=int(dns.id),
    )


def dns_answers_from_packet(
    packet: Any,
) -> list[DNSAnswer]:
    if not packet.haslayer(DNS):
        return []

    dns = packet[DNS]

    if dns.qr != 1:
        return []

    if not dns.an:
        return []

    answers: list[DNSAnswer] = []

    record = dns.an

    while record is not None:
        record_type = int(record.type)

        name = _decode(record.rrname)
        value = None

        if record_type in {
            1,
            28,
            5,
            2,
            12,
            16,
        }:
            value = _decode(record.rdata)

        elif record_type == 15:
            value = _decode(record.exchange)

        else:
            value = _decode(record.rdata)

        if name is not None and value is not None:
            answers.append(
                DNSAnswer(
                    name=name.rstrip("."),
                    record_type=_query_type(record_type),
                    value=value.rstrip("."),
                    ttl=(
                        int(record.ttl)
                        if getattr(record, "ttl", None) is not None
                        else None
                    ),
                )
            )

        record = record.payload

        if not hasattr(record, "type"):
            break

    return answers


def dns_response_metadata_from_packet(
    packet: Any,
) -> tuple[int, int, Any] | None:
    if not packet.haslayer(IP):
        return None

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    if dns.qr != 1:
        return None

    return (
        int(dns.id),
        int(dns.rcode),
        packet_timestamp(packet),
    )