from wiretap.capture.flow import Flow
from wiretap.models import (
    DNSTransaction,
    EntityRef,
    KnowledgeModel,
    SMBFileOperation,
    SMBSessionSetup,
    SMBTreeConnect,
    TLSCertificate,
    TLSTransaction,
)


class RelationshipTracker:
    """
    Compatibility layer around the knowledge model.

    Protocol-specific code can continue calling the existing
    RelationshipTracker API while relationships are stored in
    the central KnowledgeModel.
    """

    def __init__(
        self,
        knowledge: KnowledgeModel | None = None,
    ) -> None:
        self.knowledge = (
            knowledge
            if knowledge is not None
            else KnowledgeModel()
        )

    def add(
        self,
        source: EntityRef,
        relation: str,
        target: EntityRef,
        timestamp,
    ) -> None:
        self.knowledge.add_relationship(
            source=source,
            relation=relation,
            target=target,
            timestamp=timestamp,
        )

    def add_flow(
        self,
        flow: Flow,
    ) -> None:
        if flow.initiator is None:
            return

        if flow.responder is None:
            return

        self.add(
            source=EntityRef(
                type="host",
                value=flow.initiator.ip,
            ),
            relation="connects_to",
            target=EntityRef(
                type="host",
                value=flow.responder.ip,
            ),
            timestamp=flow.first_seen,
        )

        if flow.responder.port is None:
            return

        self.add(
            source=EntityRef(
                type="host",
                value=flow.responder.ip,
            ),
            relation="runs",
            target=EntityRef(
                type="service",
                value=(
                    f"{flow.protocol}/"
                    f"{flow.responder.port}"
                ),
            ),
            timestamp=flow.first_seen,
        )

    def add_dns_transaction(
        self,
        transaction: DNSTransaction,
    ) -> None:
        query = transaction.query

        self.add(
            source=EntityRef(
                type="host",
                value=query.source_ip,
            ),
            relation="queried",
            target=EntityRef(
                type="hostname",
                value=query.query,
            ),
            timestamp=query.timestamp,
        )

        for answer in transaction.answers:
            if answer.record_type not in {
                "A",
                "AAAA",
            }:
                continue

            self.add(
                source=EntityRef(
                    type="hostname",
                    value=answer.name,
                ),
                relation="resolves_to",
                target=EntityRef(
                    type="host",
                    value=answer.value,
                ),
                timestamp=transaction.timestamp,
            )

    def add_tls_transaction(
        self,
        transaction: TLSTransaction,
    ) -> None:
        hello = transaction.client_hello

        if hello is None:
            return

        if hello.server_name is None:
            return

        self.add(
            source=EntityRef(
                type="host",
                value=hello.source_ip,
            ),
            relation="accessed",
            target=EntityRef(
                type="hostname",
                value=hello.server_name,
            ),
            timestamp=hello.timestamp,
        )

    def add_tls_certificate(
        self,
        certificate: TLSCertificate,
    ) -> None:
        certificate_ref = EntityRef(
            type="certificate",
            value=certificate.fingerprint_sha256,
        )

        self.add(
            source=EntityRef(
                type="host",
                value=certificate.source_ip,
            ),
            relation="presented_certificate",
            target=certificate_ref,
            timestamp=certificate.timestamp,
        )

    def add_smb_session_setup(
        self,
        observation: SMBSessionSetup,
    ) -> None:
        if not observation.username:
            return

        identity = observation.username

        if observation.domain:
            identity = (
                f"{observation.domain}\\"
                f"{identity}"
            )

        self.add(
            source=EntityRef(
                type="host",
                value=observation.source_ip,
            ),
            relation="authenticated_as",
            target=EntityRef(
                type="identity",
                value=identity,
            ),
            timestamp=observation.timestamp,
        )

    def add_smb_tree_connect(
        self,
        observation: SMBTreeConnect,
    ) -> None:
        if not observation.share:
            return

        self.add(
            source=EntityRef(
                type="host",
                value=observation.source_ip,
            ),
            relation="accessed_share",
            target=EntityRef(
                type="share",
                value=observation.share,
            ),
            timestamp=observation.timestamp,
        )

    def add_smb_file_operation(
        self,
        observation: SMBFileOperation,
    ) -> None:
        path = (
            observation.resolved_path
            or observation.path
        )

        if not path:
            return

        relation = {
            "CREATE": "created_path",
            "READ": "reads_from",
            "WRITE": "writes_to",
            "CLOSE": "closed_path",
        }.get(
            observation.operation,
            "accessed_path",
        )

        self.add(
            source=EntityRef(
                type="host",
                value=observation.source_ip,
            ),
            relation=relation,
            target=EntityRef(
                type="path",
                value=path,
            ),
            timestamp=observation.timestamp,
        )

    def relationships(self):
        return self.knowledge.relationships()