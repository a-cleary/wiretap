from wiretap.capture.flow import Flow
from wiretap.models import (
    DNSTransaction,
    EntityRef,
    Relationship,
    TLSCertificate,
    TLSTransaction,
    SMBFileOperation,
    SMBSessionSetup,
    SMBTreeConnect,
)


class RelationshipTracker:
    def __init__(self) -> None:
        self._relationships: dict[
            tuple[EntityRef, str, EntityRef],
            Relationship,
        ] = {}

    def add(
        self,
        source: EntityRef,
        relation: str,
        target: EntityRef,
        timestamp,
    ) -> None:
        key = (
            source,
            relation,
            target,
        )

        relationship = self._relationships.get(key)

        if relationship is None:
            self._relationships[key] = Relationship(
                source=source,
                relation=relation,
                target=target,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            return

        self._relationships[key] = Relationship(
            source=relationship.source,
            relation=relationship.relation,
            target=relationship.target,
            first_seen=min(
                relationship.first_seen,
                timestamp,
            ),
            last_seen=max(
                relationship.last_seen,
                timestamp,
            ),
        )

    def add_flow(self, flow: Flow) -> None:
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
        if not observation.path:
            return

        self.add(
            source=EntityRef(
                type="host",
                value=observation.source_ip,
            ),
            relation="accessed_path",
            target=EntityRef(
                type="path",
                value=observation.path,
            ),
            timestamp=observation.timestamp,
        )

    def relationships(self) -> list[Relationship]:
        return list(
            self._relationships.values()
        )