from dataclasses import dataclass
from datetime import datetime


@dataclass
class Host:
    ip: str
    first_seen: datetime
    last_seen: datetime