from dataclasses import dataclass
from datetime import datetime


@dataclass
class SMBObservation:
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    version: str
    command: str
    message_type: str
    message_id: int | None = None
    session_id: int | None = None
    tree_id: int | None = None


@dataclass
class SMBNegotiate(SMBObservation):
    dialect: str | None = None
    dialects: list[str] | None = None


@dataclass
class SMBSessionSetup(SMBObservation):
    username: str | None = None
    domain: str | None = None
    workstation: str | None = None


@dataclass
class SMBTreeConnect(SMBObservation):
    share: str | None = None
    share_type: str | None = None


@dataclass
class SMBFileOperation(SMBObservation):
    operation: str = ""
    path: str | None = None
    filename: str | None = None
    file_id: str | None = None
    offset: int | None = None
    length: int | None = None
    resolved_path: str | None = None
    identity: str | None = None
    share: str | None = None


@dataclass
class SMBTransaction:
    request: SMBObservation | None = None
    response: SMBObservation | None = None