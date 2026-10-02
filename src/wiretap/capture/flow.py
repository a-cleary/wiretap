from dataclasses import dataclass
from datetime import datetime

from wiretap.models import Connection, Endpoint


@dataclass(frozen=True)
class FlowKey:
    endpoint_a: tuple[str, int | None]
    endpoint_b: tuple[str, int | None]
    protocol: str

    @classmethod
    def from_connection(cls, connection: Connection) -> "FlowKey":
        source = (
            connection.source.ip,
            connection.source.port,
        )

        destination = (
            connection.destination.ip,
            connection.destination.port,
        )

        endpoints = sorted([source, destination])

        return cls(
            endpoint_a=endpoints[0],
            endpoint_b=endpoints[1],
            protocol=connection.protocol,
        )


@dataclass
class Flow:
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: str

    first_seen: datetime
    last_seen: datetime

    packets: int = 0
    bytes: int = 0

    initiator: Endpoint | None = None
    responder: Endpoint | None = None

    initiator_packets: int = 0
    initiator_bytes: int = 0

    responder_packets: int = 0
    responder_bytes: int = 0

    def add(self, connection: Connection) -> None:
        self.first_seen = min(
            self.first_seen,
            connection.first_seen,
        )

        self.last_seen = max(
            self.last_seen,
            connection.last_seen,
        )

        self.packets += connection.packets
        self.bytes += connection.bytes

        self._update_roles(connection)

        if self.initiator == connection.source:
            self.initiator_packets += connection.packets
            self.initiator_bytes += connection.bytes

        elif self.responder == connection.source:
            self.responder_packets += connection.packets
            self.responder_bytes += connection.bytes

    def _update_roles(self, connection: Connection) -> None:
        if self.initiator is not None:
            return

        if connection.protocol.lower() == "tcp":
            flags = connection.tcp_flags or 0

            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            # SYN without ACK = connection initiator
            if syn and not ack:
                self.initiator = connection.source
                self.responder = connection.destination
                return

            # SYN-ACK = responder
            if syn and ack:
                self.initiator = connection.destination
                self.responder = connection.source
                return

        # Fallback for protocols without a usable handshake.
        self.initiator = connection.source
        self.responder = connection.destination


class FlowTracker:
    def __init__(self) -> None:
        self._flows: dict[FlowKey, Flow] = {}

    def add(self, connection: Connection) -> None:
        key = FlowKey.from_connection(connection)

        flow = self._flows.get(key)

        if flow is None:
            flow = Flow(
                endpoint_a=Endpoint(
                    ip=key.endpoint_a[0],
                    port=key.endpoint_a[1],
                ),
                endpoint_b=Endpoint(
                    ip=key.endpoint_b[0],
                    port=key.endpoint_b[1],
                ),
                protocol=connection.protocol,
                first_seen=connection.first_seen,
                last_seen=connection.last_seen,
            )

            self._flows[key] = flow

        flow.add(connection)

    def flows(self) -> list[Flow]:
        return list(self._flows.values())