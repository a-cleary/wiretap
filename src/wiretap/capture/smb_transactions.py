from dataclasses import dataclass

from wiretap.models import (
    SMBObservation,
    SMBTransaction,
)


@dataclass(frozen=True)
class SMBFlowKey:
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None

    @classmethod
    def from_observation(
        cls,
        observation: SMBObservation,
    ) -> "SMBFlowKey":
        if observation.message_type == "request":
            return cls(
                client_ip=observation.source_ip,
                client_port=observation.source_port,
                server_ip=observation.destination_ip,
                server_port=observation.destination_port,
            )

        return cls(
            client_ip=observation.destination_ip,
            client_port=observation.destination_port,
            server_ip=observation.source_ip,
            server_port=observation.source_port,
        )


class SMBTransactionTracker:
    def __init__(self) -> None:
        self._pending: dict[
            tuple[SMBFlowKey, int],
            SMBObservation,
        ] = {}

        self._transactions: list[
            SMBTransaction
        ] = []

    def add(
        self,
        observation: SMBObservation,
    ) -> None:
        if observation.message_id is None:
            return

        key = (
            SMBFlowKey.from_observation(
                observation
            ),
            observation.message_id,
        )

        if observation.message_type == "request":
            self._pending[key] = observation
            return

        request = self._pending.pop(
            key,
            None,
        )

        self._transactions.append(
            SMBTransaction(
                request=request,
                response=observation,
            )
        )

    def transactions(
        self,
    ) -> list[SMBTransaction]:
        return list(self._transactions)

    def pending(
        self,
    ) -> list[SMBObservation]:
        return list(self._pending.values())