from dataclasses import dataclass
from datetime import datetime

from wiretap.capture.flow import Flow
from wiretap.models import (
    Connection,
    DNSQuery,
    DNSTransaction,
    Hostname,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    Relationship,
    Service,
)

from wiretap.output.jsonl import (
    connection_to_dict,
    dns_query_to_dict,
    dns_transaction_to_dict,
    flow_to_dict,
    hostname_to_dict,
    http_request_to_dict,
    http_response_to_dict,
    http_transaction_to_dict,
    relationship_to_dict,
    service_to_dict,
)


@dataclass(frozen=True)
class TimelineRecord:
    timestamp: datetime
    record_type: str
    data: dict


def connection_to_timeline(
    connection: Connection,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=connection.first_seen,
        record_type="connection",
        data=connection_to_dict(connection),
    )


def flow_to_timeline(
    flow: Flow,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=flow.first_seen,
        record_type="flow",
        data=flow_to_dict(flow),
    )


def dns_to_timeline(
    query: DNSQuery,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=query.timestamp,
        record_type="dns_query",
        data=dns_query_to_dict(query),
    )


def dns_transaction_to_timeline(
    transaction: DNSTransaction,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=transaction.timestamp,
        record_type="dns_transaction",
        data=dns_transaction_to_dict(transaction),
    )


def http_to_timeline(
    request: HTTPRequest,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=request.timestamp,
        record_type="http_request",
        data=http_request_to_dict(request),
    )


def http_response_to_timeline(
    response: HTTPResponse,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=response.timestamp,
        record_type="http_response",
        data=http_response_to_dict(response),
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
            "HTTP transaction contains no request or response"
        )

    return TimelineRecord(
        timestamp=timestamp,
        record_type="http_transaction",
        data=http_transaction_to_dict(transaction),
    )


def hostname_to_timeline(
    hostname: Hostname,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=hostname.first_seen,
        record_type="hostname",
        data=hostname_to_dict(hostname),
    )


def service_to_timeline(
    service: Service,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=service.first_seen,
        record_type="service",
        data=service_to_dict(service),
    )


def relationship_to_timeline(
    relationship: Relationship,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=relationship.first_seen,
        record_type="relationship",
        data=relationship_to_dict(relationship),
    )


def observation_to_timeline(
    observation,
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


def sort_timeline(
    records: list[TimelineRecord],
) -> list[TimelineRecord]:
    return sorted(
        records,
        key=lambda record: record.timestamp,
    )