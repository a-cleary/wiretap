from wiretap.capture.dns import (
    dns_answers_from_packet,
    dns_response_metadata_from_packet,
)
from wiretap.capture.dns_transactions import (
    DNSTransactionTracker,
)
from wiretap.capture.entities import EntityTracker
from wiretap.capture.flow import FlowTracker
from wiretap.capture.http_transactions import (
    HTTPTransactionTracker,
)
from wiretap.capture.parsers import parse_packet
from wiretap.capture.relationships import RelationshipTracker
from wiretap.capture.smb_transactions import (
    SMBTransactionTracker,
)
from wiretap.capture.tls_transactions import (
    TLSTransactionTracker,
)
from wiretap.models import (
    DNSQuery,
    HTTPRequest,
    HTTPResponse,
    SMBFileOperation,
    SMBObservation,
    SMBSessionSetup,
    SMBTreeConnect,
    TLSCertificate,
    TLSClientHello,
    TLSServerHello,
)
from wiretap.capture.smb_files import (
    SMBFileTracker,
)
from wiretap.capture.smb_context import (
    SMBContextTracker,
)


class CaptureProcessor:
    def __init__(self) -> None:
        self.flow_tracker = FlowTracker()
        self.entity_tracker = EntityTracker()
        self.relationship_tracker = RelationshipTracker()

        self.http_tracker = HTTPTransactionTracker()
        self.dns_tracker = DNSTransactionTracker()
        self.tls_tracker = TLSTransactionTracker()
        self.smb_tracker = SMBTransactionTracker()
        self.smb_file_tracker = SMBFileTracker()
        self.smb_context_tracker = SMBContextTracker()

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

            elif isinstance(observation, TLSClientHello):
                self.tls_tracker.add_client_hello(
                    observation
                )

            elif isinstance(observation, TLSServerHello):
                self.tls_tracker.add_server_hello(
                    observation
                )

            elif isinstance(observation, TLSCertificate):
                self.entity_tracker.add_tls_certificate(
                    observation
                )
                self.relationship_tracker.add_tls_certificate(
                    observation
                )

            elif isinstance(observation, SMBObservation):
                self.smb_tracker.add(observation)

                if isinstance(
                    observation,
                    SMBSessionSetup,
                ):
                    self.smb_context_tracker.add_session_setup(
                        observation
                    )
                    self.entity_tracker.add_smb_session_setup(
                        observation
                    )
                    self.relationship_tracker.add_smb_session_setup(
                        observation
                    )

                elif isinstance(
                    observation,
                    SMBTreeConnect,
                ):
                    self.smb_context_tracker.add_tree_connect(
                        observation
                    )
                    self.entity_tracker.add_smb_tree_connect(
                        observation
                    )
                    self.relationship_tracker.add_smb_tree_connect(
                        observation
                    )

                elif isinstance(
                    observation,
                    SMBFileOperation,
                ):
                    self.entity_tracker.add_smb_file_operation(
                        observation
                    )
                    self.relationship_tracker.add_smb_file_operation(
                        observation
                    )

        response = dns_response_metadata_from_packet(packet)

        if response is not None:
            (
                transaction_id,
                response_code,
                timestamp,
            ) = response

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

        for transaction in self.tls_tracker.transactions():
            self.entity_tracker.add_tls_transaction(
                transaction
            )
            self.relationship_tracker.add_tls_transaction(
                transaction
            )

        for transaction in self.smb_tracker.transactions():
            self.smb_file_tracker.add_transaction(
                transaction
            )

        for index, observation in enumerate(
            self.observations
        ):
            if not isinstance(
                observation,
                SMBFileOperation,
            ):
                continue

            resolved = (
                self.smb_file_tracker.resolve_operation(
                    observation
                )
            )

            resolved = (
                self.smb_context_tracker.resolve_operation(
                    resolved
                )
            )

            self.observations[index] = resolved

            self.relationship_tracker.add_smb_file_operation(
                resolved
            )