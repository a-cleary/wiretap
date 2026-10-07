import json

from wiretap.cli import main


def test_cli_outputs_jsonl(test_pcap, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--jsonl",
        ],
    )

    main()

    output = capsys.readouterr().out
    lines = output.strip().splitlines()

    records = [
        json.loads(line)
        for line in lines
    ]

    record_types = [
        record["type"]
        for record in records
    ]

    assert record_types.count("flow") == 4
    assert record_types.count("dns_query") == 1
    assert record_types.count("dns_transaction") == 1
    assert record_types.count("http_request") == 1
    assert record_types.count("http_response") == 1
    assert record_types.count("http_transaction") == 1
    assert record_types.count("hostname") == 1
    assert record_types.count("service") == 4
    assert record_types.count("relationship") == 9

    services = [
        record
        for record in records
        if record["type"] == "service"
    ]

    assert len(services) == 4

    assert {
        service["id"]
        for service in services
    } == {
        "service:tcp/80",
        "service:tcp/445",
        "service:tcp/88",
        "service:udp/53",
    }

    service_by_id = {
        service["id"]: service
        for service in services
    }

    assert service_by_id["service:tcp/80"][
        "host_ip"
    ] == "10.10.10.20"

    assert service_by_id["service:tcp/80"][
        "port"
    ] == 80

    assert service_by_id["service:tcp/80"][
        "protocol"
    ] == "tcp"

    transactions = [
        record
        for record in records
        if record["type"] == "http_transaction"
    ]

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction["request"]["method"] == "GET"
    assert transaction["request"]["host"] == (
        "fileserver.corp.local"
    )
    assert transaction["request"]["path"] == "/admin/login"

    assert transaction["response"]["status_code"] == 200
    assert transaction["response"]["server"] == (
        "nginx/1.24.0"
    )

    dns_transactions = [
        record
        for record in records
        if record["type"] == "dns_transaction"
    ]

    assert len(dns_transactions) == 1

    dns_transaction = dns_transactions[0]

    assert dns_transaction["query"]["name"] == (
        "fileserver.corp.local"
    )

    assert dns_transaction["query"]["type"] == "A"

    assert dns_transaction["query"]["transaction_id"] == 1234

    assert dns_transaction["response_code"] == 0

    assert dns_transaction["answers"][0]["value"] == (
        "10.10.10.20"
    )

    hostnames = [
        record
        for record in records
        if record["type"] == "hostname"
    ]

    assert len(hostnames) == 1

    assert hostnames[0]["name"] == (
        "fileserver.corp.local"
    )

    relationships = [
        record
        for record in records
        if record["type"] == "relationship"
    ]

    assert len(relationships) == 9

    assert {
        (
            relationship["source"],
            relationship["relation"],
            relationship["target"],
        )
        for relationship in relationships
    } == {
        (
            "host:10.10.10.42",
            "connects_to",
            "host:10.10.10.20",
        ),
        (
            "host:10.10.10.42",
            "connects_to",
            "host:10.10.10.30",
        ),
        (
            "host:10.10.10.42",
            "connects_to",
            "host:10.10.10.10",
        ),
        (
            "host:10.10.10.20",
            "runs",
            "service:tcp/80",
        ),
        (
            "host:10.10.10.30",
            "runs",
            "service:tcp/445",
        ),
        (
            "host:10.10.10.10",
            "runs",
            "service:tcp/88",
        ),
        (
            "host:10.10.10.10",
            "runs",
            "service:udp/53",
        ),
        (
            "host:10.10.10.42",
            "queried",
            "hostname:fileserver.corp.local",
        ),
        (
            "hostname:fileserver.corp.local",
            "resolves_to",
            "host:10.10.10.20",
        ),
    }

    assert all(
        "source_type" in relationship
        for relationship in relationships
    )

    assert all(
        "target_type" in relationship
        for relationship in relationships
    )


def test_cli_host_query(test_pcap, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--host",
            "10.10.10.20",
        ],
    )

    main()

    output = capsys.readouterr().out
    result = json.loads(output)

    assert result["host"]["ip"] == "10.10.10.20"

    assert {
        service["port"]
        for service in result["services"]
    } == {80}


def test_cli_host_query_unknown_host(
    test_pcap,
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--host",
            "10.10.10.99",
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == "Host not found: 10.10.10.99"
    else:
        raise AssertionError(
            "Expected SystemExit"
        )

    assert capsys.readouterr().out == ""


def test_cli_related_query(
    test_pcap,
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--related",
            "10.10.10.42",
        ],
    )

    main()

    output = capsys.readouterr().out
    result = json.loads(output)

    assert {
        entity["id"]
        for entity in result
    } == {
        "host:10.10.10.20",
        "host:10.10.10.30",
        "host:10.10.10.10",
        "hostname:fileserver.corp.local",
    }


def test_cli_related_query_with_relation(
    test_pcap,
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--related",
            "10.10.10.42",
            "--relation",
            "queried",
        ],
    )

    main()

    output = capsys.readouterr().out
    result = json.loads(output)

    assert result == [
        {
            "id": "hostname:fileserver.corp.local",
            "type": "hostname",
            "value": "fileserver.corp.local",
        }
    ]


def test_cli_traverse_query(
    test_pcap,
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--traverse",
            "10.10.10.42",
            "--depth",
            "2",
        ],
    )

    main()

    output = capsys.readouterr().out
    result = json.loads(output)

    assert {
        entity["id"]
        for entity in result["entities"]
    } == {
        "host:10.10.10.42",
        "host:10.10.10.20",
        "host:10.10.10.30",
        "host:10.10.10.10",
        "hostname:fileserver.corp.local",
        "service:tcp/80",
        "service:tcp/445",
        "service:tcp/88",
        "service:udp/53",
    }


def test_cli_traverse_query_jsonl(
    test_pcap,
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--traverse",
            "10.10.10.42",
            "--depth",
            "1",
            "--jsonl",
        ],
    )

    main()

    output = capsys.readouterr().out
    lines = output.strip().splitlines()

    records = [
        json.loads(line)
        for line in lines
    ]

    assert all(
        record["type"]
        in {"entity", "relationship"}
        for record in records
    )

    assert any(
        record["id"] == "host:10.10.10.20"
        for record in records
    )

    assert any(
        record["id"] == "host:10.10.10.42:connects_to:host:10.10.10.20"
        for record in records
        if record["type"] == "relationship"
    )


def test_cli_rejects_relation_without_query(
    test_pcap,
    monkeypatch,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--relation",
            "runs",
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError(
            "Expected SystemExit"
        )


def test_cli_rejects_negative_depth(
    test_pcap,
    monkeypatch,
):
    monkeypatch.setattr(
        "sys.argv",
        [
            "wiretap",
            str(test_pcap),
            "--traverse",
            "10.10.10.42",
            "--depth",
            "-1",
        ],
    )

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError(
            "Expected SystemExit"
        )