from dataclasses import dataclass
from datetime import datetime


@dataclass
class Endpoint:
    ip: str
    port: int | None = None


@dataclass
class Connection:
    source: Endpoint
    destination: Endpoint
    protocol: str
    first_seen: datetime
    last_seen: datetime
    packets: int = 0
    bytes: int = 0
    tcp_flags: int | None = None