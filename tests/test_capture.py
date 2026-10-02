from wiretap.capture import PcapReader
from wiretap.capture.connections import connection_from_packet
from wiretap.capture.dns import dns_query_from_packet
from wiretap.capture.http import http_request_from_packet
from wiretap.capture.http import http_response_from_packet


def test_pcap_reader(test_pcap):
    reader = PcapReader(test_pcap)

    packets = list(reader.read())

    assert len(packets) == 8


def test_connection_extraction(test_pcap):
    reader = PcapReader(test_pcap)

    connections = []

    for packet in reader.read():
        connection = connection_from_packet(packet)

        if connection is not None:
            connections.append(connection)

    assert len(connections) == 8


def test_dns_query_extraction(test_pcap):
    reader = PcapReader(test_pcap)

    queries = []

    for packet in reader.read():
        query = dns_query_from_packet(packet)

        if query is not None:
            queries.append(query)

    assert len(queries) == 1

    query = queries[0]

    assert query.source_ip == "10.10.10.42"
    assert query.destination_ip == "10.10.10.10"
    assert query.query == "fileserver.corp.local"
    assert query.query_type == "A"


def test_http_request_extraction(test_pcap):
    reader = PcapReader(test_pcap)

    requests = []

    for packet in reader.read():
        request = http_request_from_packet(packet)

        if request is not None:
            requests.append(request)

    assert len(requests) == 1

    request = requests[0]

    assert request.source_ip == "10.10.10.42"
    assert request.source_port == 49152
    assert request.destination_ip == "10.10.10.20"
    assert request.destination_port == 80

    assert request.method == "GET"
    assert request.host == "fileserver.corp.local"
    assert request.path == "/admin/login"
    assert request.version == "HTTP/1.1"
    assert request.user_agent == "WiretapTest/1.0"


def test_http_response_extraction(test_pcap):
    reader = PcapReader(test_pcap)

    responses = []

    for packet in reader.read():
        response = http_response_from_packet(packet)

        if response is not None:
            responses.append(response)

    assert len(responses) == 1

    response = responses[0]

    assert response.source_ip == "10.10.10.20"
    assert response.source_port == 80
    assert response.destination_ip == "10.10.10.42"
    assert response.destination_port == 49152

    assert response.version == "HTTP/1.1"
    assert response.status_code == 200
    assert response.reason == "OK"
    assert response.server == "nginx/1.24.0"
    assert response.content_type == "text/html"
    assert response.content_length == 18432
    assert response.location is None