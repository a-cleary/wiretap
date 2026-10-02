from dataclasses import dataclass

from wiretap.models import (
    TLSClientHello,
    TLSServerHello,
    TLSTransaction,
)


@dataclass(frozen=True)
class TLSFlowKey:
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None

    @classmethod
    def from_client_hello(
        cls,
        hello: TLSClientHello,
    ) -> "TLSFlowKey":
        return cls(
            client_ip=hello.source_ip,
            client_port=hello.source_port,
            server_ip=hello.destination_ip,
            server_port=hello.destination_port,
        )

    @classmethod
    def from_server_hello(
        cls,
        hello: TLSServerHello,
    ) -> "TLSFlowKey":
        return cls(
            client_ip=hello.destination_ip,
            client_port=hello.destination_port,
            server_ip=hello.source_ip,
            server_port=hello.source_port,
        )


class TLSTransactionTracker:
    def __init__(self) -> None:
        self._pending: dict[
            TLSFlowKey,
            TLSClientHello,
        ] = {}

        self._transactions: list[
            TLSTransaction
        ] = []

    def add_client_hello(
        self,
        hello: TLSClientHello,
    ) -> None:
        key = TLSFlowKey.from_client_hello(
            hello
        )

        self._pending[key] = hello

    def add_server_hello(
        self,
        hello: TLSServerHello,
    ) -> None:
        key = TLSFlowKey.from_server_hello(
            hello
        )

        client_hello = self._pending.pop(
            key,
            None,
        )

        if client_hello is None:
            self._transactions.append(
                TLSTransaction(
                    client_hello=None,
                    server_hello=hello,
                )
            )
            return

        self._transactions.append(
            TLSTransaction(
                client_hello=client_hello,
                server_hello=hello,
            )
        )

    def transactions(
        self,
    ) -> list[TLSTransaction]:
        return list(self._transactions)

    def pending_client_hellos(
        self,
    ) -> list[TLSClientHello]:
        return list(self._pending.values())