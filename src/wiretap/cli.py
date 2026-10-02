import argparse
import json

from wiretap.capture.processor import CaptureProcessor
from wiretap.capture.reader import PcapReader
from wiretap.output.timeline import (
    dns_transaction_to_timeline,
    flow_to_timeline,
    hostname_to_timeline,
    http_transaction_to_timeline,
    observation_to_timeline,
    relationship_to_timeline,
    service_to_timeline,
    sort_timeline,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wiretap",
        description=(
            "Red-team network intelligence "
            "extraction from PCAP files"
        ),
    )

    parser.add_argument(
        "capture",
        help="Path to a PCAP or PCAPNG file",
    )

    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Output JSONL records",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    reader = PcapReader(args.capture)
    processor = CaptureProcessor()

    for packet in reader.read():
        processor.process_packet(packet)

    processor.finalize()

    if args.jsonl:
        timeline = []

        for flow in processor.flow_tracker.flows():
            timeline.append(
                flow_to_timeline(flow)
            )

        for observation in processor.observations:
            timeline.append(
                observation_to_timeline(
                    observation
                )
            )

        for transaction in (
            processor.http_tracker.transactions()
        ):
            timeline.append(
                http_transaction_to_timeline(
                    transaction
                )
            )

        for transaction in (
            processor.dns_tracker.transactions()
        ):
            timeline.append(
                dns_transaction_to_timeline(
                    transaction
                )
            )

        for hostname in (
            processor.entity_tracker.hostnames()
        ):
            timeline.append(
                hostname_to_timeline(hostname)
            )

        for service in (
            processor.entity_tracker.services()
        ):
            timeline.append(
                service_to_timeline(service)
            )

        for relationship in (
            processor.relationship_tracker.relationships()
        ):
            timeline.append(
                relationship_to_timeline(
                    relationship
                )
            )

        for record in sort_timeline(timeline):
            print(
                json.dumps(
                    record.data,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )