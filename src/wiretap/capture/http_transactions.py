from dataclasses import dataclass

from wiretap.models import (
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
)


@dataclass(frozen=True)
class HTTPFlowKey:
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None

    @classmethod
    def from_request(
        cls,
        request: HTTPRequest,
    ) -> "HTTPFlowKey":
        return cls(
            source_ip=request.source_ip,
            source_port=request.source_port,
            destination_ip=request.destination_ip,
            destination_port=request.destination_port,
        )

    @classmethod
    def from_response(
        cls,
        response: HTTPResponse,
    ) -> "HTTPFlowKey":
        return cls(
            source_ip=response.destination_ip,
            source_port=response.destination_port,
            destination_ip=response.source_ip,
            destination_port=response.source_port,
        )


class HTTPTransactionTracker:
    def __init__(self) -> None:
        self._pending: dict[
            HTTPFlowKey,
            list[HTTPRequest],
        ] = {}

        self._transactions: list[HTTPTransaction] = []

    def add_request(
        self,
        request: HTTPRequest,
    ) -> None:
        key = HTTPFlowKey.from_request(request)

        pending = self._pending.setdefault(key, [])

        pending.append(request)

    def add_response(
        self,
        response: HTTPResponse,
    ) -> None:
        key = HTTPFlowKey.from_response(response)

        pending = self._pending.get(key)

        if not pending:
            self._transactions.append(
                HTTPTransaction(
                    request=None,
                    response=response,
                )
            )
            return

        request = pending.pop(0)

        self._transactions.append(
            HTTPTransaction(
                request=request,
                response=response,
            )
        )

        if not pending:
            del self._pending[key]

    def transactions(self) -> list[HTTPTransaction]:
        return list(self._transactions)

    def pending_requests(self) -> list[HTTPRequest]:
        requests = []

        for pending in self._pending.values():
            requests.extend(pending)

        return requests