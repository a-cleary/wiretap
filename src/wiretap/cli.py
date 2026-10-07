import argparse
import json
from dataclasses import fields, is_dataclass

from wiretap.capture.processor import CaptureProcessor
from wiretap.capture.reader import PcapReader
from wiretap.models import EntityRef
from wiretap.output.timeline import (
    dns_transaction_to_timeline,
    flow_to_timeline,
    hostname_to_timeline,
    http_transaction_to_timeline,
    observation_to_timeline,
    relationship_to_timeline,
    service_to_timeline,
    smb_transaction_to_timeline,
    sort_timeline,
    tls_transaction_to_timeline,
)
from wiretap.query import QueryEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wiretap",
        description=(
            "Network intelligence extraction "
            "and analysis from PCAP files"
        ),
    )

    parser.add_argument(
        "capture",
        help="Path to a PCAP or PCAPNG file",
    )

    query_group = parser.add_mutually_exclusive_group()

    query_group.add_argument(
        "--host",
        metavar="IP",
        help="Show context for a host",
    )

    query_group.add_argument(
        "--related",
        metavar="IP",
        help="Show entities directly related to a host",
    )

    query_group.add_argument(
        "--traverse",
        metavar="IP",
        help="Traverse relationships starting from a host",
    )

    parser.add_argument(
        "--relation",
        metavar="RELATION",
        help="Restrict relationship queries to a specific relation",
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Traversal depth (default: 1)",
    )

    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Output timeline records as JSONL",
    )

    return parser


def _process_capture(
    capture: str,
) -> CaptureProcessor:
    reader = PcapReader(capture)
    processor = CaptureProcessor()

    for packet in reader.read():
        processor.process_packet(packet)

    processor.finalize()

    return processor


def _entity_to_dict(
    entity: EntityRef,
) -> dict:
    return {
        "id": entity.id,
        "type": entity.type,
        "value": entity.value,
    }


def _entity_record(
    entity: EntityRef,
) -> dict:
    return {
        "type": "entity",
        "id": entity.id,
        "entity_type": entity.type,
        "value": entity.value,
    }


def _relationship_to_dict(
    relationship,
) -> dict:
    return {
        "id": relationship.id,
        "source": relationship.source.id,
        "relation": relationship.relation,
        "target": relationship.target.id,
        "first_seen": relationship.first_seen.isoformat(),
        "last_seen": relationship.last_seen.isoformat(),
    }


def _relationship_record(
    relationship,
) -> dict:
    return {
        "type": "relationship",
        **_relationship_to_dict(relationship),
    }


def _serialize(
    value,
):
    if isinstance(value, EntityRef):
        return _entity_to_dict(value)

    if is_dataclass(value):
        return {
            field.name: _serialize(
                getattr(value, field.name)
            )
            for field in fields(value)
        }

    if isinstance(value, list):
        return [
            _serialize(item)
            for item in value
        ]

    if isinstance(value, dict):
        return {
            key: _serialize(item)
            for key, item in value.items()
        }

    return value


def _print_json(
    value,
) -> None:
    print(
        json.dumps(
            _serialize(value),
            indent=2,
            sort_keys=True,
            default=str,
        )
    )


def _print_query(
    processor: CaptureProcessor,
    args: argparse.Namespace,
) -> bool:
    query = QueryEngine(
        knowledge=processor.knowledge
    )

    if args.host is not None:
        context = query.host(args.host)

        if context is None:
            raise SystemExit(
                f"Host not found: {args.host}"
            )

        _print_json(context)
        return True

    if args.related is not None:
        source = EntityRef(
            type="host",
            value=args.related,
        )

        entities = query.related(
            entity=source,
            relation=args.relation,
        )

        _print_json(entities)
        return True

    if args.traverse is not None:
        source = EntityRef(
            type="host",
            value=args.traverse,
        )

        result = query.traverse(
            start=source,
            depth=args.depth,
            relation=args.relation,
        )

        if args.jsonl:
            for entity in result.entities:
                print(
                    json.dumps(
                        _entity_record(entity),
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )

            for relationship in result.relationships:
                print(
                    json.dumps(
                        _relationship_record(
                            relationship
                        ),
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )

        else:
            _print_json(result)

        return True

    return False


def _print_timeline_jsonl(
    processor: CaptureProcessor,
) -> None:
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
        processor.smb_tracker.transactions()
    ):
        timeline.append(
            smb_transaction_to_timeline(
                transaction
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
        processor.tls_tracker.transactions()
    ):
        timeline.append(
            tls_transaction_to_timeline(
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


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.depth < 0:
        parser.error(
            "--depth must be greater than or equal to zero"
        )

    processor = _process_capture(
        args.capture
    )

    if _print_query(
        processor,
        args,
    ):
        return

    if args.relation is not None:
        parser.error(
            "--relation requires --related or --traverse"
        )

    if args.depth != 1:
        parser.error(
            "--depth requires --traverse"
        )

    if args.jsonl:
        _print_timeline_jsonl(processor)