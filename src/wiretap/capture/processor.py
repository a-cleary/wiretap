from wiretap.capture.dns import (
    dns_answers_from_packet,
    dns_response_metadata_from_packet,
)
from wiretap.capture.dns_transactions import (
    DNSTransactionTracker,
)
from wiretap.capture.flow import FlowTracker
from wiretap.capture.http_transactions import (
    HTTPTransactionTracker,
)
from wiretap.capture.parsers import parse_packet
from wiretap.models import DNSQuery, HTTPRequest, HTTPResponse
from wiretap.capture.entities import EntityTracker
from wiretap.capture.relationships import RelationshipTracker


class CaptureProcessor:
    def __init__(self) -> None:
        self.flow_tracker = FlowTracker()
        self.entity_tracker = EntityTracker()
        self.http_tracker = HTTPTransactionTracker()
        self.dns_tracker = DNSTransactionTracker()
        self.relationship_tracker = RelationshipTracker()

        self.observations = []

    def process_packet(self, packet) -> None:
        from wiretap.capture.connections import (
            connection_from_packet,
        )

        connection = connection_from_packet(packet)

        if connection is not None:
            self.flow_tracker.add(connection)

        observations = parse_packet(packet)

        for observation in observations:
            self.observations.append(observation)

            if isinstance(observation, DNSQuery):
                self.dns_tracker.add_query(observation)

            elif isinstance(observation, HTTPRequest):
                self.http_tracker.add_request(observation)

            elif isinstance(observation, HTTPResponse):
                self.http_tracker.add_response(observation)

        response = dns_response_metadata_from_packet(packet)

        if response is not None:
            transaction_id, response_code, timestamp = response

            ip = packet["IP"]

            self.dns_tracker.add_response(
                source_ip=ip.src,
                destination_ip=ip.dst,
                transaction_id=transaction_id,
                answers=dns_answers_from_packet(packet),
                response_code=response_code,
                timestamp=timestamp,
            )

    def finalize(self) -> None:
        for flow in self.flow_tracker.flows():
            self.entity_tracker.add_flow(flow)
            self.relationship_tracker.add_flow(flow)

        for transaction in self.dns_tracker.transactions():
            self.entity_tracker.add_dns_transaction(
                transaction
            )

            self.relationship_tracker.add_dns_transaction(
                transaction
            )