from datetime import datetime, timezone

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP

from wiretap.capture.dns import (
    dns_answers_from_packet,
    dns_query_from_packet,
)


def test_dns_query_parser():
    packet = (
        Ether()
        / IP(
            src="10.10.10.42",
            dst="10.10.10.10",
        )
        / UDP(
            sport=53000,
            dport=53,
        )
        / DNS(
            id=1234,
            rd=1,
            qr=0,
            qd=DNSQR(
                qname="fileserver.corp.local"
            ),
        )
    )

    packet.time = datetime(
        2026,
        9,
        30,
        12,
        0,
        tzinfo=timezone.utc,
    ).timestamp()

    result = dns_query_from_packet(packet)

    assert result is not None
    assert result.source_ip == "10.10.10.42"
    assert result.destination_ip == "10.10.10.10"
    assert result.query == "fileserver.corp.local"
    assert result.query_type == "A"


def test_dns_a_answer_parser():
    packet = (
        Ether()
        / IP(
            src="10.10.10.10",
            dst="10.10.10.42",
        )
        / UDP(
            sport=53,
            dport=53000,
        )
        / DNS(
            id=1234,
            qr=1,
            aa=1,
            qd=DNSQR(
                qname="fileserver.corp.local"
            ),
            an=DNSRR(
                rrname="fileserver.corp.local",
                type="A",
                ttl=300,
                rdata="10.10.10.20",
            ),
        )
    )

    answers = dns_answers_from_packet(packet)

    assert len(answers) == 1

    answer = answers[0]

    assert answer.name == "fileserver.corp.local"
    assert answer.record_type == "A"
    assert answer.value == "10.10.10.20"
    assert answer.ttl == 300


def test_dns_cname_answer_parser():
    packet = (
        Ether()
        / IP(
            src="10.10.10.10",
            dst="10.10.10.42",
        )
        / UDP(
            sport=53,
            dport=53000,
        )
        / DNS(
            id=1234,
            qr=1,
            qd=DNSQR(
                qname="portal.corp.local"
            ),
            an=DNSRR(
                rrname="portal.corp.local",
                type="CNAME",
                ttl=300,
                rdata="web01.corp.local",
            ),
        )
    )

    answers = dns_answers_from_packet(packet)

    assert len(answers) == 1

    answer = answers[0]

    assert answer.name == "portal.corp.local"
    assert answer.record_type == "CNAME"
    assert answer.value == "web01.corp.local"
    assert answer.ttl == 300