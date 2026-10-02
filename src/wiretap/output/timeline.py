from dataclasses import dataclass
from datetime import datetime
from typing import Any

from wiretap.capture.flow import Flow

from wiretap.models import (
    DNSQuery,
    DNSTransaction,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    Relationship,
    Hostname,
)

from wiretap.output.jsonl import (
    dns_query_to_dict,
    flow_to_dict,
    http_request_to_dict,
    http_response_to_dict,
    http_transaction_to_dict,
    dns_transaction_to_dict,
    relationship_to_dict,
    hostname_to_dict,
)

@dataclass
class TimelineRecord:
    timestamp: datetime
    record_type: str
    data: dict[str, Any]


def flow_to_timeline(flow: Flow) -> TimelineRecord:
    return TimelineRecord(
        timestamp=flow.first_seen,
        record_type="flow",
        data=flow_to_dict(flow),
    )


def dns_to_timeline(query: DNSQuery) -> TimelineRecord:
    return TimelineRecord(
        timestamp=query.timestamp,
        record_type="dns_query",
        data=dns_query_to_dict(query),
    )


def http_to_timeline(request: HTTPRequest) -> TimelineRecord:
    return TimelineRecord(
        timestamp=request.timestamp,
        record_type="http_request",
        data={
            "type": "http_request",
            "timestamp": request.timestamp.isoformat().replace(
                "+00:00",
                "Z",
            ),
            "source": {
                "ip": request.source_ip,
            },
            "destination": {
                "ip": request.destination_ip,
            },
            "method": request.method,
            "host": request.host,
            "path": request.path,
            "version": request.version,
            "user_agent": request.user_agent,
        },
    )


def http_response_to_timeline(
    response: HTTPResponse,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=response.timestamp,
        record_type="http_response",
        data=http_response_to_dict(response),
    )


def observation_to_timeline(
    observation: DNSQuery | HTTPRequest | HTTPResponse,
) -> TimelineRecord:
    if isinstance(observation, DNSQuery):
        return dns_to_timeline(observation)

    if isinstance(observation, HTTPRequest):
        return http_to_timeline(observation)

    if isinstance(observation, HTTPResponse):
        return http_response_to_timeline(observation)

    raise TypeError(
        f"Unsupported observation type: "
        f"{type(observation).__name__}"
    )


def http_to_timeline(request: HTTPRequest) -> TimelineRecord:
    return TimelineRecord(
        timestamp=request.timestamp,
        record_type="http_request",
        data=http_request_to_dict(request),
    )


def http_transaction_to_timeline(
    transaction: HTTPTransaction,
) -> TimelineRecord:
    if transaction.request is not None:
        timestamp = transaction.request.timestamp
    elif transaction.response is not None:
        timestamp = transaction.response.timestamp
    else:
        raise ValueError(
            "HTTP transaction has neither request nor response"
        )

    return TimelineRecord(
        timestamp=timestamp,
        record_type="http_transaction",
        data=http_transaction_to_dict(transaction),
    )


def dns_transaction_to_timeline(
    transaction: DNSTransaction,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=transaction.timestamp,
        record_type="dns_transaction",
        data=dns_transaction_to_dict(transaction),
    )


def relationship_to_timeline(
    relationship: Relationship,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=relationship.first_seen,
        record_type="relationship",
        data=relationship_to_dict(relationship),
    )


def hostname_to_timeline(
    hostname: Hostname,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=hostname.first_seen,
        record_type="hostname",
        data=hostname_to_dict(hostname),
    )


def sort_timeline(
    records: list[TimelineRecord],
) -> list[TimelineRecord]:
    return sorted(
        records,
        key=lambda record: record.timestamp,
    )