from dataclasses import dataclass
from datetime import datetime


@dataclass
class Hostname:
    name: str
    first_seen: datetime
    last_seen: datetime