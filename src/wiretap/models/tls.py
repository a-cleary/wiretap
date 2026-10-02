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
class TLSCertificate:
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    fingerprint_sha256: str
    subject: str | None
    issuer: str | None
    serial_number: str | None
    not_before: datetime | None
    not_after: datetime | None
    subject_alt_names: list[str]


@dataclass
class TLSTransaction:
    client_hello: TLSClientHello | None = None
    server_hello: TLSServerHello | None = None