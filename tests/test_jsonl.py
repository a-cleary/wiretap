def test_relationship_to_dict():
    from datetime import datetime, timezone

    from wiretap.models import EntityRef, Relationship
    from wiretap.output.jsonl import relationship_to_dict

    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    relationship = Relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.42",
        ),
        relation="queried",
        target=EntityRef(
            type="hostname",
            value="fileserver.corp.local",
        ),
        first_seen=timestamp,
        last_seen=timestamp,
    )

    result = relationship_to_dict(relationship)

    assert result == {
        "type": "relationship",
        "timestamp": "2026-01-01T00:00:01Z",
        "first_seen": "2026-01-01T00:00:01Z",
        "last_seen": "2026-01-01T00:00:01Z",
        "source": "host:10.10.10.42",
        "source_type": "host",
        "target": "hostname:fileserver.corp.local",
        "target_type": "hostname",
        "relation": "queried",
    }


def test_service_to_dict():
    from datetime import datetime, timezone

    from wiretap.models import Service
    from wiretap.output.jsonl import service_to_dict

    timestamp = datetime(
        2026,
        1,
        1,
        0,
        0,
        1,
        tzinfo=timezone.utc,
    )

    service = Service(
        host_ip="10.10.10.20",
        port=80,
        protocol="tcp",
        first_seen=timestamp,
        last_seen=timestamp,
    )

    result = service_to_dict(service)

    assert result == {
        "type": "service",
        "timestamp": "2026-01-01T00:00:01Z",
        "first_seen": "2026-01-01T00:00:01Z",
        "last_seen": "2026-01-01T00:00:01Z",
        "host_ip": "10.10.10.20",
        "port": 80,
        "protocol": "tcp",
        "id": "service:tcp/80",
    }