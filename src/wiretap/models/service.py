from dataclasses import dataclass
from datetime import datetime


@dataclass
class Service:
    host_ip: str
    port: int
    protocol: str
    first_seen: datetime
    last_seen: datetime