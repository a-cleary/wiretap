from dataclasses import dataclass
from datetime import datetime


@dataclass
class TLSClientHello:
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    version: str
    server_name: str | None
    alpn_protocols: list[str]
    cipher_suites: list[str]


@dataclass
class TLSServerHello:
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    version: str
    cipher_suite: str | None
    alpn_protocol: str | None


@dataclass
class TLSTransaction:
    client_hello: TLSClientHello | None = None
    server_hello: TLSServerHello | None = None