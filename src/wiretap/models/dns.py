from dataclasses import dataclass
from datetime import datetime


@dataclass
class DNSQuery:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    query: str
    query_type: str
    transaction_id: int | None = None


@dataclass
class DNSAnswer:
    name: str
    record_type: str
    value: str
    ttl: int | None = None


@dataclass
class DNSTransaction:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    query: DNSQuery
    answers: list[DNSAnswer]
    response_code: int