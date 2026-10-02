from dataclasses import dataclass
from datetime import datetime

from wiretap.models.entity import EntityRef


@dataclass(frozen=True)
class Relationship:
    source: EntityRef
    relation: str
    target: EntityRef
    first_seen: datetime
    last_seen: datetime