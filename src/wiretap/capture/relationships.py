from wiretap.capture.flow import Flow
from wiretap.models import DNSTransaction, Relationship


class RelationshipTracker:
    def __init__(self) -> None:
        self._relationships: dict[
            tuple[str, str, str],
            Relationship,
        ] = {}

    def add(
        self,
        source: str,
        relation: str,
        target: str,
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
            source=flow.initiator.ip,
            relation="connects_to",
            target=flow.responder.ip,
            timestamp=flow.first_seen,
        )

    def add_dns_transaction(
        self,
        transaction: DNSTransaction,
    ) -> None:
        query = transaction.query

        self.add(
            source=query.source_ip,
            relation="queried",
            target=query.query,
            timestamp=query.timestamp,
        )

        for answer in transaction.answers:
            if answer.record_type == "A":
                self.add(
                    source=answer.name,
                    relation="resolves_to",
                    target=answer.value,
                    timestamp=transaction.timestamp,
                )

            elif answer.record_type == "AAAA":
                self.add(
                    source=answer.name,
                    relation="resolves_to",
                    target=answer.value,
                    timestamp=transaction.timestamp,
                )

    def relationships(self) -> list[Relationship]:
        return list(self._relationships.values())