from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap


def create_test_pcap(path: Path) -> None:
    packets = [
        # HTTP-like TCP traffic
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.20",
        ) / TCP(
            sport=49152,
            dport=80,
        ),

        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.20",
        ) / TCP(
            sport=49152,
            dport=80,
        ),

        # SMB
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.30",
        ) / TCP(
            sport=49153,
            dport=445,
        ),

        # Kerberos
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.10",
        ) / TCP(
            sport=49154,
            dport=88,
        ),

        # DNS
        Ether() / IP(
            src="10.10.10.42",
            dst="10.10.10.10",
        ) / UDP(
            sport=53000,
            dport=53,
        ) / DNS(
            rd=1,
            qd=DNSQR(qname="fileserver.corp.local"),
        ),
    ]

    wrpcap(str(path), packets)


if __name__ == "__main__":
    output = Path("tests/fixtures/test_capture.pcap")
    output.parent.mkdir(parents=True, exist_ok=True)

    create_test_pcap(output)
    print(f"Created {output}")