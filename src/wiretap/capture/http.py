from typing import Any

from scapy.layers.http import (
    HTTPRequest as ScapyHTTPRequest,
    HTTPResponse as ScapyHTTPResponse,
)
from scapy.layers.inet import IP, TCP

from wiretap.capture.connections import packet_timestamp
from wiretap.models import HTTPRequest, HTTPResponse


def _decode(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return str(value)


def http_request_from_packet(packet: Any) -> HTTPRequest | None:
    if not packet.haslayer(IP):
        return None

    if not packet.haslayer(TCP):
        return None

    if not packet.haslayer(ScapyHTTPRequest):
        return None

    request = packet[ScapyHTTPRequest]
    ip = packet[IP]
    tcp = packet[TCP]

    method = _decode(request.Method)
    path = _decode(request.Path)
    version = _decode(request.Http_Version)
    host = _decode(request.Host)
    user_agent = _decode(request.User_Agent)

    if method is None or path is None:
        return None

    return HTTPRequest(
        timestamp=packet_timestamp(packet),
        source_ip=ip.src,
        source_port=int(tcp.sport),
        destination_ip=ip.dst,
        destination_port=int(tcp.dport),
        method=method,
        host=host,
        path=path,
        version=version or "HTTP/1.1",
        user_agent=user_agent,
    )


def http_response_from_packet(packet: Any) -> HTTPResponse | None:
    if not packet.haslayer(IP):
        return None

    if not packet.haslayer(TCP):
        return None

    if not packet.haslayer(ScapyHTTPResponse):
        return None

    response = packet[ScapyHTTPResponse]
    ip = packet[IP]
    tcp = packet[TCP]

    version = _decode(response.Http_Version)
    status_code = _decode(response.Status_Code)
    reason = _decode(response.Reason_Phrase)

    if status_code is None:
        return None

    server = _decode(response.Server)
    content_type = _decode(response.Content_Type)
    content_length = _decode(response.Content_Length)
    location = _decode(response.Location)

    try:
        parsed_status_code = int(status_code)
    except ValueError:
        return None

    parsed_content_length = None

    if content_length is not None:
        try:
            parsed_content_length = int(content_length)
        except ValueError:
            pass

    return HTTPResponse(
        timestamp=packet_timestamp(packet),
        source_ip=ip.src,
        source_port=int(tcp.sport),
        destination_ip=ip.dst,
        destination_port=int(tcp.dport),
        version=version or "HTTP/1.1",
        status_code=parsed_status_code,
        reason=reason,
        server=server,
        content_type=content_type,
        content_length=parsed_content_length,
        location=location,
    )