from dataclasses import dataclass


@dataclass(frozen=True)
class EntityRef:
    """
    A stable reference to an entity in the Wiretap knowledge model.

    Examples:
        host:10.10.10.42
        service:tcp/445
        hostname:fileserver.corp.local
        identity:CORP\\alice
        share:\\\\10.10.10.30\\ADMIN$
        path:\\Temp\\payload.exe
        certificate:abcdef123...
    """

    type: str
    value: str

    @property
    def id(self) -> str:
        return f"{self.type}:{self.value}"