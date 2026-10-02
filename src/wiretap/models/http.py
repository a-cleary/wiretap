from dataclasses import dataclass
from datetime import datetime


@dataclass
class HTTPRequest:
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    method: str
    host: str | None
    path: str
    version: str
    user_agent: str | None


@dataclass
class HTTPResponse:
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    version: str
    status_code: int
    reason: str | None
    server: str | None
    content_type: str | None
    content_length: int | None
    location: str | None


@dataclass
class HTTPTransaction:
    request: HTTPRequest | None = None
    response: HTTPResponse | None = None