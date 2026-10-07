from dataclasses import dataclass
from datetime import datetime

from wiretap.models.entity import EntityRef


@dataclass(frozen=True)
class Relationship:
    """
    A time-bounded relationship between two entities.

    Examples:
        host --connects_to--> host
        host --runs--> service
        host --queried--> hostname
        hostname --resolves_to--> host
        host --authenticated_as--> identity
        host --accessed_share--> share
        host --writes_to--> path
    """

    source: EntityRef
    relation: str
    target: EntityRef
    first_seen: datetime
    last_seen: datetime

    @property
    def id(self) -> str:
        return (
            f"{self.source.id}:"
            f"{self.relation}:"
            f"{self.target.id}"
        )