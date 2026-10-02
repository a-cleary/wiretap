from dataclasses import dataclass


@dataclass(frozen=True)
class EntityRef:
    type: str
    value: str

    @property
    def id(self) -> str:
        return f"{self.type}:{self.value}"