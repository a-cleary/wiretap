from datetime import datetime, timezone

import pytest

from wiretap.models import (
    EntityRef,
    KnowledgeModel,
)
from wiretap.query import (
    QueryEngine,
    QueryTraversal,
)


def timestamp(
    second: int,
) -> datetime:
    return datetime(
        2026,
        1,
        1,
        0,
        0,
        second,
        tzinfo=timezone.utc,
    )


def build_knowledge_model() -> KnowledgeModel:
    knowledge = KnowledgeModel()

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    host_b = EntityRef(
        type="host",
        value="10.10.10.20",
    )

    service = EntityRef(
        type="service",
        value="tcp/445",
    )

    share = EntityRef(
        type="share",
        value=r"\\10.10.10.20\ADMIN$",
    )

    path = EntityRef(
        type="path",
        value=r"\Temp\payload.exe",
    )

    knowledge.add_host(
        ip="10.10.10.10",
        first_seen=timestamp(1),
        last_seen=timestamp(5),
    )

    knowledge.add_host(
        ip="10.10.10.20",
        first_seen=timestamp(2),
        last_seen=timestamp(6),
    )

    knowledge.add_service(
        host_ip="10.10.10.20",
        port=445,
        protocol="tcp",
        first_seen=timestamp(2),
        last_seen=timestamp(6),
    )

    knowledge.add_share(
        share=share.value
    )

    knowledge.add_path(
        path=path.value
    )

    knowledge.add_relationship(
        source=host_a,
        relation="connects_to",
        target=host_b,
        timestamp=timestamp(2),
    )

    knowledge.add_relationship(
        source=host_b,
        relation="runs",
        target=service,
        timestamp=timestamp(3),
    )

    knowledge.add_relationship(
        source=host_a,
        relation="accessed_share",
        target=share,
        timestamp=timestamp(4),
    )

    knowledge.add_relationship(
        source=share,
        relation="contains",
        target=path,
        timestamp=timestamp(5),
    )

    return knowledge


def test_related_returns_outgoing_targets():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    related = query.related(host_a)

    assert {
        entity.id
        for entity in related
    } == {
        "host:10.10.10.20",
        r"share:\\10.10.10.20\ADMIN$",
    }


def test_related_can_filter_by_relation():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    related = query.related(
        host_a,
        relation="connects_to",
    )

    assert [
        entity.id
        for entity in related
    ] == [
        "host:10.10.10.20"
    ]


def test_targets_is_alias_for_related():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    assert query.targets(host_a) == (
        query.related(host_a)
    )


def test_sources_returns_incoming_sources():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_b = EntityRef(
        type="host",
        value="10.10.10.20",
    )

    sources = query.sources(
        host_b,
        relation="connects_to",
    )

    assert [
        entity.id
        for entity in sources
    ] == [
        "host:10.10.10.10"
    ]


def test_sources_can_return_multiple_relationship_sources():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    path = EntityRef(
        type="path",
        value=r"\Temp\payload.exe",
    )

    sources = query.sources(path)

    assert [
        entity.id
        for entity in sources
    ] == [
        r"share:\\10.10.10.20\ADMIN$"
    ]


def test_traverse_depth_zero_returns_start():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    result = query.traverse(
        host_a,
        depth=0,
    )

    assert isinstance(
        result,
        QueryTraversal,
    )

    assert [
        entity.id
        for entity in result.entities
    ] == [
        "host:10.10.10.10"
    ]

    assert result.relationships == []


def test_traverse_depth_one():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    result = query.traverse(
        host_a,
        depth=1,
    )

    assert {
        entity.id
        for entity in result.entities
    } == {
        "host:10.10.10.10",
        "host:10.10.10.20",
        r"share:\\10.10.10.20\ADMIN$",
    }

    assert {
        relationship.id
        for relationship
        in result.relationships
    } == {
        (
            "host:10.10.10.10:"
            "connects_to:"
            "host:10.10.10.20"
        ),
        (
            "host:10.10.10.10:"
            "accessed_share:"
            r"share:\\10.10.10.20\ADMIN$"
        ),
    }


def test_traverse_depth_two():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    result = query.traverse(
        host_a,
        depth=2,
    )

    assert {
        entity.id
        for entity in result.entities
    } == {
        "host:10.10.10.10",
        "host:10.10.10.20",
        "service:tcp/445",
        r"share:\\10.10.10.20\ADMIN$",
        r"path:\Temp\payload.exe",
    }

    assert {
        relationship.id
        for relationship
        in result.relationships
    } == {
        (
            "host:10.10.10.10:"
            "connects_to:"
            "host:10.10.10.20"
        ),
        (
            "host:10.10.10.10:"
            "accessed_share:"
            r"share:\\10.10.10.20\ADMIN$"
        ),
        (
            "host:10.10.10.20:"
            "runs:"
            "service:tcp/445"
        ),
        (
            r"share:\\10.10.10.20\ADMIN$:"
            "contains:"
            r"path:\Temp\payload.exe"
        ),
    }


def test_traverse_can_filter_relationship_type():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    result = query.traverse(
        host_a,
        depth=2,
        relation="connects_to",
    )

    assert {
        entity.id
        for entity in result.entities
    } == {
        "host:10.10.10.10",
        "host:10.10.10.20",
    }

    assert len(
        result.relationships
    ) == 1

    assert (
        result.relationships[0].relation
        == "connects_to"
    )


def test_traverse_deduplicates_entities():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    knowledge = query.knowledge

    knowledge.add_relationship(
        source=EntityRef(
            type="host",
            value="10.10.10.20",
        ),
        relation="connects_to",
        target=host_a,
        timestamp=timestamp(7),
    )

    result = query.traverse(
        host_a,
        depth=3,
    )

    ids = [
        entity.id
        for entity in result.entities
    ]

    assert len(ids) == len(set(ids))


def test_traverse_deduplicates_relationships():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    result = query.traverse(
        host_a,
        depth=3,
    )

    relationship_ids = [
        relationship.id
        for relationship
        in result.relationships
    ]

    assert len(
        relationship_ids
    ) == len(
        set(relationship_ids)
    )


def test_traverse_negative_depth_is_rejected():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    host_a = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    with pytest.raises(
        ValueError,
        match="depth must be greater than or equal to zero",
    ):
        query.traverse(
            host_a,
            depth=-1,
        )


def test_traverse_stops_when_no_more_entities_exist():
    query = QueryEngine(
        knowledge=build_knowledge_model()
    )

    service = EntityRef(
        type="service",
        value="tcp/445",
    )

    result = query.traverse(
        service,
        depth=10,
    )

    assert {
        entity.id
        for entity in result.entities
    } == {
        "service:tcp/445",
    }

    assert result.relationships == []