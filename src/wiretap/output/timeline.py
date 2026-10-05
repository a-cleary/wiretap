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
    SMBFileOperation,
    SMBSessionSetup,
    SMBTreeConnect,
    SMBTransaction,
    Service,
    TLSClientHello,
    TLSServerHello,
    TLSTransaction,
    TLSCertificate,
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
    smb_file_operation_to_dict,
    smb_session_setup_to_dict,
    smb_tree_connect_to_dict,
    smb_transaction_to_dict,
    tls_client_hello_to_dict,
    tls_server_hello_to_dict,
    tls_transaction_to_dict,
    tls_certificate_to_dict,
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


def smb_session_setup_to_timeline(
    observation: SMBSessionSetup,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=observation.timestamp,
        record_type="smb_session_setup",
        data=smb_session_setup_to_dict(
            observation
        ),
    )


def smb_tree_connect_to_timeline(
    observation: SMBTreeConnect,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=observation.timestamp,
        record_type="smb_tree_connect",
        data=smb_tree_connect_to_dict(
            observation
        ),
    )


def smb_file_operation_to_timeline(
    observation: SMBFileOperation,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=observation.timestamp,
        record_type="smb_file_operation",
        data=smb_file_operation_to_dict(
            observation
        ),
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

    if isinstance(
        observation,
        TLSClientHello,
    ):
        return tls_client_hello_to_timeline(
            observation
        )

    if isinstance(
        observation,
        TLSServerHello,
    ):
        return tls_server_hello_to_timeline(
            observation
        )

    if isinstance(
        observation,
        TLSCertificate,
    ):
        return tls_certificate_to_timeline(
            observation
        )

    if isinstance(
        observation,
        SMBSessionSetup,
    ):
        return smb_session_setup_to_timeline(
            observation
        )

    if isinstance(
        observation,
        SMBTreeConnect,
    ):
        return smb_tree_connect_to_timeline(
            observation
        )

    if isinstance(
        observation,
        SMBFileOperation,
    ):
        return smb_file_operation_to_timeline(
            observation
        )

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


def tls_client_hello_to_timeline(
    hello: TLSClientHello,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=hello.timestamp,
        record_type="tls_client_hello",
        data=tls_client_hello_to_dict(hello),
    )


def tls_server_hello_to_timeline(
    hello: TLSServerHello,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=hello.timestamp,
        record_type="tls_server_hello",
        data=tls_server_hello_to_dict(hello),
    )


def tls_transaction_to_timeline(
    transaction: TLSTransaction,
) -> TimelineRecord:
    if transaction.client_hello is not None:
        timestamp = transaction.client_hello.timestamp
    elif transaction.server_hello is not None:
        timestamp = transaction.server_hello.timestamp
    else:
        raise ValueError(
            "TLS transaction contains no hello"
        )

    return TimelineRecord(
        timestamp=timestamp,
        record_type="tls_transaction",
        data=tls_transaction_to_dict(transaction),
    )


def tls_certificate_to_timeline(
    certificate: TLSCertificate,
) -> TimelineRecord:
    return TimelineRecord(
        timestamp=certificate.timestamp,
        record_type="tls_certificate",
        data=tls_certificate_to_dict(
            certificate
        ),
    )


def smb_transaction_to_timeline(
    transaction: SMBTransaction,
) -> TimelineRecord:
    if transaction.request is not None:
        timestamp = transaction.request.timestamp
    elif transaction.response is not None:
        timestamp = transaction.response.timestamp
    else:
        raise ValueError(
            "SMB transaction contains no request or response"
        )

    return TimelineRecord(
        timestamp=timestamp,
        record_type="smb_transaction",
        data=smb_transaction_to_dict(
            transaction
        ),
    )