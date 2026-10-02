from typing import Any, Callable

from wiretap.capture.dns import dns_query_from_packet
from wiretap.capture.http import (
    http_request_from_packet,
    http_response_from_packet,
)


Parser = Callable[[Any], Any | None]


PARSERS: list[Parser] = [
    dns_query_from_packet,
    http_request_from_packet,
    http_response_from_packet,
]


def parse_packet(packet: Any) -> list[Any]:
    observations = []

    for parser in PARSERS:
        observation = parser(packet)

        if observation is not None:
            observations.append(observation)

    return observations