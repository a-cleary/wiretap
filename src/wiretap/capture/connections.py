from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import IP, TCP, UDP

from wiretap.models import Connection, Endpoint


def packet_timestamp(packet: Any) -> datetime:
    timestamp = float(packet.time)

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    )


def connection_from_packet(packet: Any) -> Connection | None:
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    protocol: str
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: int | None = None

    if packet.haslayer(TCP):
        protocol = "tcp"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        tcp_flags = int(packet[TCP].flags)

    elif packet.haslayer(UDP):
        protocol = "udp"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    else:
        protocol = str(ip.proto)

    timestamp = packet_timestamp(packet)

    return Connection(
        source=Endpoint(
            ip=ip.src,
            port=source_port,
        ),
        destination=Endpoint(
            ip=ip.dst,
            port=destination_port,
        ),
        protocol=protocol,
        first_seen=timestamp,
        last_seen=timestamp,
        packets=1,
        bytes=len(packet),
        tcp_flags=tcp_flags,
    )