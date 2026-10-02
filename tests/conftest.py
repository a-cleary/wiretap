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

from scapy.layers.tls.handshake import (
    TLSClientHello,
    TLSServerHello,
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


class FakeServerName:
    def __init__(self, name):
        self.servername = name


class FakeServerNameExtension:
    def __init__(self, name):
        self.servernames = [
            FakeServerName(name)
        ]


class FakeALPNExtension:
    def __init__(self, protocols):
        self.protocols = protocols


class FakeClientHello:
    def __init__(
        self,
        version,
        server_name,
        alpn_protocols,
        cipher_suites,
    ):
        self.version = version

        self.ext = [
            FakeServerNameExtension(
                server_name
            ),
            FakeALPNExtension(
                alpn_protocols
            ),
        ]

        self.ciphers = cipher_suites


class FakeServerHello:
    def __init__(
        self,
        version,
        cipher_suite,
        alpn_protocol,
    ):
        self.version = version
        self.cipher = cipher_suite

        self.ext = [
            FakeALPNExtension(
                [alpn_protocol]
            )
        ]


class FakeTLSPacket:
    """
    Minimal packet wrapper for TLS parser tests.

    The TLS parser only relies on Scapy-like haslayer()
    and [] access, while connection tracking also relies
    on packet.time and len(packet).
    """

    def __init__(
        self,
        ip,
        tcp,
        handshake,
        handshake_type,
        timestamp,
    ):
        self._ip = ip
        self._tcp = tcp
        self._handshake = handshake
        self._handshake_type = handshake_type
        self.time = timestamp

    def haslayer(self, layer):
        if layer is IP:
            return True

        if layer is TCP:
            return True

        if layer is self._handshake_type:
            return True

        return False

    def __getitem__(self, layer):
        if layer is IP:
            return self._ip

        if layer is TCP:
            return self._tcp

        if layer is self._handshake_type:
            return self._handshake

        raise KeyError(layer)

    def __len__(self):
        """
        Return a realistic packet length.

        The exact size isn't important for the TLS tests, but
        connection_from_packet() uses len(packet) for byte
        accounting.
        """
        return 100


@pytest.fixture
def tls_packets():
    """
    Synthetic TLS ClientHello and ServerHello packets.

    These deliberately use ordinary Python objects for the TLS
    handshake payloads. Constructing Scapy TLS handshake objects
    initializes Scapy's TLS crypto/session machinery, which is
    unnecessary for testing Wiretap's extraction logic.
    """

    client_ip = "10.10.10.42"
    server_ip = "10.10.10.20"

    client_port = 49153
    server_port = 443

    client_ip_layer = IP(
        src=client_ip,
        dst=server_ip,
    )

    client_tcp_layer = TCP(
        sport=client_port,
        dport=server_port,
        flags="PA",
    )

    server_ip_layer = IP(
        src=server_ip,
        dst=client_ip,
    )

    server_tcp_layer = TCP(
        sport=server_port,
        dport=client_port,
        flags="PA",
    )

    client_hello = FakeClientHello(
        version=0x0303,
        server_name="fileserver.corp.local",
        alpn_protocols=[
            "h2",
            "http/1.1",
        ],
        cipher_suites=[
            0x1301,
            0x1302,
            0x1303,
        ],
    )

    server_hello = FakeServerHello(
        version=0x0303,
        cipher_suite=0x1301,
        alpn_protocol="h2",
    )

    client_packet = FakeTLSPacket(
        ip=client_ip_layer,
        tcp=client_tcp_layer,
        handshake=client_hello,
        handshake_type=TLSClientHello,
        timestamp=1767268801.0,
    )

    server_packet = FakeTLSPacket(
        ip=server_ip_layer,
        tcp=server_tcp_layer,
        handshake=server_hello,
        handshake_type=TLSServerHello,
        timestamp=1767268801.01,
    )

    return [
        client_packet,
        server_packet,
    ]