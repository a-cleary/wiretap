import json
from datetime import datetime, timezone
from typing import Any

from wiretap.capture.flow import Flow
from wiretap.models import (
    Connection,
    DNSQuery,
    DNSTransaction,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    Relationship,
    Hostname,
)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.isoformat().replace("+00:00", "Z")


def connection_to_dict(connection: Connection) -> dict[str, Any]:
    return {
        "type": "connection",
        "protocol": connection.protocol.lower(),
        "source": {
            "ip": connection.source.ip,
            "port": connection.source.port,
        },
        "destination": {
            "ip": connection.destination.ip,
            "port": connection.destination.port,
        },
        "first_seen": _timestamp(connection.first_seen),
        "last_seen": _timestamp(connection.last_seen),
        "packets": connection.packets,
        "bytes": connection.bytes,
    }


def flow_to_dict(flow: Flow) -> dict[str, Any]:
    return {
        "type": "flow",
        "protocol": flow.protocol.lower(),
        "initiator": {
            "ip": flow.initiator.ip if flow.initiator else None,
            "port": flow.initiator.port if flow.initiator else None,
        },
        "responder": {
            "ip": flow.responder.ip if flow.responder else None,
            "port": flow.responder.port if flow.responder else None,
        },
        "first_seen": _timestamp(flow.first_seen),
        "last_seen": _timestamp(flow.last_seen),
        "packets": flow.packets,
        "bytes": flow.bytes,
        "direction": {
            "initiator_to_responder": {
                "packets": flow.initiator_packets,
                "bytes": flow.initiator_bytes,
            },
            "responder_to_initiator": {
                "packets": flow.responder_packets,
                "bytes": flow.responder_bytes,
            },
        },
    }


def serialize_connection(connection: Connection) -> str:
    return json.dumps(
        connection_to_dict(connection),
        separators=(",", ":"),
        sort_keys=True,
    )


def serialize_flow(flow: Flow) -> str:
    return json.dumps(
        flow_to_dict(flow),
        separators=(",", ":"),
        sort_keys=True,
    )


def dns_query_to_dict(query: DNSQuery) -> dict[str, Any]:
    return {
        "type": "dns_query",
        "timestamp": _timestamp(query.timestamp),
        "source": {
            "ip": query.source_ip,
        },
        "destination": {
            "ip": query.destination_ip,
        },
        "query": query.query,
        "query_type": query.query_type,
    }


def serialize_dns_query(query: DNSQuery) -> str:
    return json.dumps(
        dns_query_to_dict(query),
        separators=(",", ":"),
        sort_keys=True,
    )


def http_request_to_dict(request: HTTPRequest) -> dict[str, Any]:
    return {
        "type": "http_request",
        "timestamp": _timestamp(request.timestamp),
        "source": {
            "ip": request.source_ip,
            "port": request.source_port,
        },
        "destination": {
            "ip": request.destination_ip,
            "port": request.destination_port,
        },
        "method": request.method,
        "host": request.host,
        "path": request.path,
        "version": request.version,
        "user_agent": request.user_agent,
    }


def http_response_to_dict(
    response: HTTPResponse,
) -> dict[str, Any]:
    return {
        "type": "http_response",
        "timestamp": _timestamp(response.timestamp),
        "source": {
            "ip": response.source_ip,
            "port": response.source_port,
        },
        "destination": {
            "ip": response.destination_ip,
            "port": response.destination_port,
        },
        "version": response.version,
        "status_code": response.status_code,
        "reason": response.reason,
        "server": response.server,
        "content_type": response.content_type,
        "content_length": response.content_length,
        "location": response.location,
    }


def http_transaction_to_dict(
    transaction: HTTPTransaction,
) -> dict[str, Any]:
    return {
        "type": "http_transaction",
        "request": (
            http_request_to_dict(transaction.request)
            if transaction.request is not None
            else None
        ),
        "response": (
            http_response_to_dict(transaction.response)
            if transaction.response is not None
            else None
        ),
    }


def dns_transaction_to_dict(
    transaction: DNSTransaction,
) -> dict[str, Any]:
    return {
        "type": "dns_transaction",
        "timestamp": _timestamp(transaction.timestamp),
        "source": {
            "ip": transaction.source_ip,
        },
        "destination": {
            "ip": transaction.destination_ip,
        },
        "query": {
            "name": transaction.query.query,
            "type": transaction.query.query_type,
            "transaction_id": transaction.query.transaction_id,
        },
        "response_code": transaction.response_code,
        "answers": [
            {
                "name": answer.name,
                "type": answer.record_type,
                "value": answer.value,
                "ttl": answer.ttl,
            }
            for answer in transaction.answers
        ],
    }


def serialize_dns_transaction(
    transaction: DNSTransaction,
) -> str:
    return json.dumps(
        dns_transaction_to_dict(transaction),
        separators=(",", ":"),
        sort_keys=True,
    )


def serialize_http_transaction(
    transaction: HTTPTransaction,
) -> str:
    return json.dumps(
        http_transaction_to_dict(transaction),
        separators=(",", ":"),
        sort_keys=True,
    )


def serialize_http_response(
    response: HTTPResponse,
) -> str:
    return json.dumps(
        http_response_to_dict(response),
        separators=(",", ":"),
        sort_keys=True,
    )


def serialize_http_request(request: HTTPRequest) -> str:
    return json.dumps(
        http_request_to_dict(request),
        separators=(",", ":"),
        sort_keys=True,
    )


def relationship_to_dict(
    relationship: Relationship,
) -> dict[str, Any]:
    return {
        "type": "relationship",
        "timestamp": _timestamp(
            relationship.first_seen
        ),
        "first_seen": _timestamp(
            relationship.first_seen
        ),
        "last_seen": _timestamp(
            relationship.last_seen
        ),
        "source": relationship.source,
        "relation": relationship.relation,
        "target": relationship.target,
    }


def serialize_relationship(
    relationship: Relationship,
) -> str:
    return json.dumps(
        relationship_to_dict(relationship),
        separators=(",", ":"),
        sort_keys=True,
    )


from wiretap.models import Relationship


def relationship_to_dict(
    relationship: Relationship,
) -> dict[str, Any]:
    return {
        "type": "relationship",
        "timestamp": _timestamp(
            relationship.first_seen
        ),
        "first_seen": _timestamp(
            relationship.first_seen
        ),
        "last_seen": _timestamp(
            relationship.last_seen
        ),
        "source": relationship.source,
        "relation": relationship.relation,
        "target": relationship.target,
    }


def serialize_relationship(
    relationship: Relationship,
) -> str:
    return json.dumps(
        relationship_to_dict(relationship),
        separators=(",", ":"),
        sort_keys=True,
    )


def hostname_to_dict(
    hostname: Hostname,
) -> dict[str, Any]:
    return {
        "type": "hostname",
        "timestamp": _timestamp(
            hostname.first_seen
        ),
        "first_seen": _timestamp(
            hostname.first_seen
        ),
        "last_seen": _timestamp(
            hostname.last_seen
        ),
        "name": hostname.name,
    }


def serialize_hostname(
    hostname: Hostname,
) -> str:
    return json.dumps(
        hostname_to_dict(hostname),
        separators=(",", ":"),
        sort_keys=True,
    )