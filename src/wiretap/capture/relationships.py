from wiretap.capture.flow import Flow
from wiretap.models import (
    DNSTransaction,
    EntityRef,
    Relationship,
    TLSTransaction,
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

    def relationships(self) -> list[Relationship]:
        return list(
            self._relationships.values()
        )