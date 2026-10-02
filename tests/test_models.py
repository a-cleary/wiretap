from wiretap.models import EntityRef


def test_entity_ref_id():
    entity = EntityRef(
        type="host",
        value="10.10.10.20",
    )

    assert entity.id == "host:10.10.10.20"


def test_entity_ref_is_immutable():
    entity = EntityRef(
        type="hostname",
        value="fileserver.corp.local",
    )

    try:
        entity.value = "other.local"
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "EntityRef should be immutable"
        )


def test_entity_ref_distinguishes_entity_types():
    host = EntityRef(
        type="host",
        value="10.10.10.20",
    )

    hostname = EntityRef(
        type="hostname",
        value="10.10.10.20",
    )

    assert host.id != hostname.id