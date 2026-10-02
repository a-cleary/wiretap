from dataclasses import dataclass

from wiretap.models import (
    DNSAnswer,
    DNSQuery,
    DNSTransaction,
)


@dataclass(frozen=True)
class DNSFlowKey:
    client_ip: str
    server_ip: str
    transaction_id: int

    @classmethod
    def from_query(
        cls,
        query: DNSQuery,
    ) -> "DNSFlowKey":
        if query.transaction_id is None:
            raise ValueError(
                "DNS query has no transaction ID"
            )

        return cls(
            client_ip=query.source_ip,
            server_ip=query.destination_ip,
            transaction_id=query.transaction_id,
        )


@dataclass
class PendingDNSQuery:
    query: DNSQuery
    answers: list[DNSAnswer]
    response_code: int


class DNSTransactionTracker:
    def __init__(self) -> None:
        self._pending: dict[
            DNSFlowKey,
            DNSQuery,
        ] = {}

        self._transactions: list[DNSTransaction] = []

    def add_query(
        self,
        query: DNSQuery,
    ) -> None:
        key = DNSFlowKey.from_query(query)

        self._pending[key] = query

    def add_response(
        self,
        source_ip: str,
        destination_ip: str,
        transaction_id: int,
        answers: list[DNSAnswer],
        response_code: int,
        timestamp,
    ) -> None:
        key = DNSFlowKey(
            client_ip=destination_ip,
            server_ip=source_ip,
            transaction_id=transaction_id,
        )

        query = self._pending.pop(key, None)

        if query is None:
            return

        self._transactions.append(
            DNSTransaction(
                timestamp=timestamp,
                source_ip=query.source_ip,
                destination_ip=query.destination_ip,
                query=query,
                answers=answers,
                response_code=response_code,
            )
        )

    def transactions(self) -> list[DNSTransaction]:
        return list(self._transactions)

    def pending_queries(self) -> list[DNSQuery]:
        return list(self._pending.values())