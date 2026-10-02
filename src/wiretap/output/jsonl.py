import json
from datetime import datetime, timezone
from typing import Any

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
    TLSClientHello,
    TLSServerHello,
    TLSTransaction,
)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return (
        value.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def connection_to_dict(
    connection: Connection,
) -> dict[str, Any]:
    return {
        "type": "connection",
        "timestamp": _timestamp(
            connection.first_seen
        ),
        "first_seen": _timestamp(
            connection.first_seen
        ),
        "last_seen": _timestamp(
            connection.last_seen
        ),
        "source_ip": connection.source.ip,
        "source_port": connection.source.port,
        "destination_ip": connection.destination.ip,
        "destination_port": connection.destination.port,
        "protocol": connection.protocol,
        "packets": connection.packets,
        "bytes": connection.bytes,
        "tcp_flags": connection.tcp_flags,
    }


def serialize_connection(
    connection: Connection,
) -> str:
    return json.dumps(
        connection_to_dict(connection),
        separators=(",", ":"),
        sort_keys=True,
    )


def dns_query_to_dict(
    query: DNSQuery,
) -> dict[str, Any]:
    return {
        "type": "dns_query",
        "timestamp": _timestamp(query.timestamp),
        "source_ip": query.source_ip,
        "destination_ip": query.destination_ip,
        "name": query.query,
        "query_type": query.query_type,
        "transaction_id": query.transaction_id,
    }


def serialize_dns_query(
    query: DNSQuery,
) -> str:
    return json.dumps(
        dns_query_to_dict(query),
        separators=(",", ":"),
        sort_keys=True,
    )


def flow_to_dict(
    flow: Flow,
) -> dict[str, Any]:
    return {
        "type": "flow",
        "timestamp": _timestamp(flow.first_seen),
        "first_seen": _timestamp(flow.first_seen),
        "last_seen": _timestamp(flow.last_seen),
        "endpoint_a_ip": flow.endpoint_a.ip,
        "endpoint_a_port": flow.endpoint_a.port,
        "endpoint_b_ip": flow.endpoint_b.ip,
        "endpoint_b_port": flow.endpoint_b.port,
        "protocol": flow.protocol,
        "packets": flow.packets,
        "bytes": flow.bytes,
        "initiator_ip": (
            flow.initiator.ip
            if flow.initiator is not None
            else None
        ),
        "initiator_port": (
            flow.initiator.port
            if flow.initiator is not None
            else None
        ),
        "responder_ip": (
            flow.responder.ip
            if flow.responder is not None
            else None
        ),
        "responder_port": (
            flow.responder.port
            if flow.responder is not None
            else None
        ),
        "initiator_packets": flow.initiator_packets,
        "initiator_bytes": flow.initiator_bytes,
        "responder_packets": flow.responder_packets,
        "responder_bytes": flow.responder_bytes,
    }


def serialize_flow(
    flow: Flow,
) -> str:
    return json.dumps(
        flow_to_dict(flow),
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


def service_to_dict(
    service: Service,
) -> dict[str, Any]:
    return {
        "type": "service",
        "timestamp": _timestamp(
            service.first_seen
        ),
        "first_seen": _timestamp(
            service.first_seen
        ),
        "last_seen": _timestamp(
            service.last_seen
        ),
        "host_ip": service.host_ip,
        "port": service.port,
        "protocol": service.protocol,
        "id": (
            f"service:"
            f"{service.protocol}/"
            f"{service.port}"
        ),
    }


def serialize_service(
    service: Service,
) -> str:
    return json.dumps(
        service_to_dict(service),
        separators=(",", ":"),
        sort_keys=True,
    )


def http_request_to_dict(
    request: HTTPRequest,
) -> dict[str, Any]:
    return {
        "type": "http_request",
        "timestamp": _timestamp(request.timestamp),
        "source_ip": request.source_ip,
        "source_port": request.source_port,
        "destination_ip": request.destination_ip,
        "destination_port": request.destination_port,
        "method": request.method,
        "host": request.host,
        "path": request.path,
        "version": request.version,
        "user_agent": request.user_agent,
    }


def serialize_http_request(
    request: HTTPRequest,
) -> str:
    return json.dumps(
        http_request_to_dict(request),
        separators=(",", ":"),
        sort_keys=True,
    )


def http_response_to_dict(
    response: HTTPResponse,
) -> dict[str, Any]:
    return {
        "type": "http_response",
        "timestamp": _timestamp(response.timestamp),
        "source_ip": response.source_ip,
        "source_port": response.source_port,
        "destination_ip": response.destination_ip,
        "destination_port": response.destination_port,
        "version": response.version,
        "status_code": response.status_code,
        "reason": response.reason,
        "server": response.server,
        "content_type": response.content_type,
        "content_length": response.content_length,
        "location": response.location,
    }


def serialize_http_response(
    response: HTTPResponse,
) -> str:
    return json.dumps(
        http_response_to_dict(response),
        separators=(",", ":"),
        sort_keys=True,
    )


def http_transaction_to_dict(
    transaction: HTTPTransaction,
) -> dict[str, Any]:
    return {
        "type": "http_transaction",
        "timestamp": _timestamp(
            (
                transaction.request.timestamp
                if transaction.request is not None
                else transaction.response.timestamp
            )
        ),
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


def serialize_http_transaction(
    transaction: HTTPTransaction,
) -> str:
    return json.dumps(
        http_transaction_to_dict(transaction),
        separators=(",", ":"),
        sort_keys=True,
    )


def dns_transaction_to_dict(
    transaction: DNSTransaction,
) -> dict[str, Any]:
    return {
        "type": "dns_transaction",
        "timestamp": _timestamp(transaction.timestamp),
        "source_ip": transaction.source_ip,
        "destination_ip": transaction.destination_ip,
        "query": {
            "name": transaction.query.query,
            "type": transaction.query.query_type,
            "transaction_id": transaction.query.transaction_id,
        },
        "answers": [
            {
                "name": answer.name,
                "type": answer.record_type,
                "value": answer.value,
                "ttl": answer.ttl,
            }
            for answer in transaction.answers
        ],
        "response_code": transaction.response_code,
    }


def serialize_dns_transaction(
    transaction: DNSTransaction,
) -> str:
    return json.dumps(
        dns_transaction_to_dict(transaction),
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
        "source": relationship.source.id,
        "source_type": relationship.source.type,
        "target": relationship.target.id,
        "target_type": relationship.target.type,
        "relation": relationship.relation,
    }


def serialize_relationship(
    relationship: Relationship,
) -> str:
    return json.dumps(
        relationship_to_dict(relationship),
        separators=(",", ":"),
        sort_keys=True,
    )


def tls_client_hello_to_dict(
    hello: TLSClientHello,
) -> dict[str, Any]:
    return {
        "type": "tls_client_hello",
        "timestamp": _timestamp(
            hello.timestamp
        ),
        "source_ip": hello.source_ip,
        "source_port": hello.source_port,
        "destination_ip": hello.destination_ip,
        "destination_port": hello.destination_port,
        "version": hello.version,
        "server_name": hello.server_name,
        "alpn_protocols": hello.alpn_protocols,
        "cipher_suites": hello.cipher_suites,
    }


def serialize_tls_client_hello(
    hello: TLSClientHello,
) -> str:
    return json.dumps(
        tls_client_hello_to_dict(hello),
        separators=(",", ":"),
        sort_keys=True,
    )


def tls_server_hello_to_dict(
    hello: TLSServerHello,
) -> dict[str, Any]:
    return {
        "type": "tls_server_hello",
        "timestamp": _timestamp(
            hello.timestamp
        ),
        "source_ip": hello.source_ip,
        "source_port": hello.source_port,
        "destination_ip": hello.destination_ip,
        "destination_port": hello.destination_port,
        "version": hello.version,
        "cipher_suite": hello.cipher_suite,
        "alpn_protocol": hello.alpn_protocol,
    }


def serialize_tls_server_hello(
    hello: TLSServerHello,
) -> str:
    return json.dumps(
        tls_server_hello_to_dict(hello),
        separators=(",", ":"),
        sort_keys=True,
    )


def tls_transaction_to_dict(
    transaction: TLSTransaction,
) -> dict[str, Any]:
    return {
        "type": "tls_transaction",
        "timestamp": _timestamp(
            (
                transaction.client_hello.timestamp
                if transaction.client_hello is not None
                else transaction.server_hello.timestamp
            )
        ),
        "client_hello": (
            tls_client_hello_to_dict(
                transaction.client_hello
            )
            if transaction.client_hello is not None
            else None
        ),
        "server_hello": (
            tls_server_hello_to_dict(
                transaction.server_hello
            )
            if transaction.server_hello is not None
            else None
        ),
    }


def serialize_tls_transaction(
    transaction: TLSTransaction,
) -> str:
    return json.dumps(
        tls_transaction_to_dict(transaction),
        separators=(",", ":"),
        sort_keys=True,
    )