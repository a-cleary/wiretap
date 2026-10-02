from typing import Any, Callable

from wiretap.capture.dns import dns_query_from_packet
from wiretap.capture.http import (
    http_request_from_packet,
    http_response_from_packet,
)
from wiretap.capture.tls import (
    tls_client_hello_from_packet,
    tls_server_hello_from_packet,
)
from wiretap.capture.tls_certificates import (
    tls_certificates_from_packet,
)


Parser = Callable[[Any], Any]


PARSERS: list[Parser] = [
    dns_query_from_packet,
    http_request_from_packet,
    http_response_from_packet,
    tls_client_hello_from_packet,
    tls_server_hello_from_packet,
    tls_certificates_from_packet,
]


def parse_packet(packet: Any) -> list[Any]:
    observations = []

    for parser in PARSERS:
        result = parser(packet)

        if result is None:
            continue

        if isinstance(result, list):
            observations.extend(result)
        else:
            observations.append(result)

    return observations