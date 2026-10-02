from pathlib import Path

import pytest
from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    wrpcap,
)


@pytest.fixture
def test_pcap(tmp_path: Path) -> Path:
    path = tmp_path / "test_capture.pcap"

    packets = [
        # HTTP TCP handshake: 10.10.10.42:49152 -> 10.10.10.20:80
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.20",
        ) / TCP(
            sport=49152,
            dport=80,
            flags="S",
        ),

        Ether() / IP(
            src="10.10.10.20",
            dst="10.10.10.42",
        ) / TCP(
            sport=80,
            dport=49152,
            flags="SA",
        ),

        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.20",
        ) / TCP(
            sport=49152,
            dport=80,
            flags="PA",
        ) / Raw(
            load=(
                b"GET /admin/login HTTP/1.1\r\n"
                b"Host: fileserver.corp.local\r\n"
                b"User-Agent: WiretapTest/1.0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            ),
        ),

        Ether() / IP(
            src="10.10.10.20",
            dst="10.10.10.42",
        ) / TCP(
            sport=80,
            dport=49152,
            flags="PA",
        ) / Raw(
            load=(
                b"HTTP/1.1 200 OK\r\n"
                b"Server: nginx/1.24.0\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: 18432\r\n"
                b"\r\n"
                b"<html>login page</html>"
            ),
        ),

        # SMB connection
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.30",
        ) / TCP(
            sport=49153,
            dport=445,
            flags="S",
        ),

        # Kerberos connection
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.10",
        ) / TCP(
            sport=49154,
            dport=88,
            flags="S",
        ),

        # DNS query
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.10",
        ) / UDP(
            sport=53000,
            dport=53,
        ) / DNS(
            id=1234,
            rd=1,
            qr=0,
            qd=DNSQR(
                qname="fileserver.corp.local",
                qtype="A",
            ),
        ),

        Ether() / IP(
            src="10.10.10.10",
            dst="10.10.10.42",
        ) / UDP(
            sport=53,
            dport=53000,
        ) / DNS(
            id=1234,
            qr=1,
            aa=1,
            qd=DNSQR(
                qname="fileserver.corp.local",
                qtype="A",
            ),
            an=DNSRR(
                rrname="fileserver.corp.local",
                type="A",
                ttl=300,
                rdata="10.10.10.20",
            ),
        ),
    ]

    wrpcap(str(path), packets)

    return path