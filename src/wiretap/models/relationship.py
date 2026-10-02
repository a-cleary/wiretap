from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Relationship:
    source: str
    relation: str
    target: str
    first_seen: datetime
    last_seen: datetime