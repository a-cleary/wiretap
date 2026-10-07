from datetime import datetime, timezone

from wiretap.capture.processor import CaptureProcessor
from wiretap.models import EntityRef, KnowledgeModel


def test_capture_processor_creates_knowledge_model():
    processor = CaptureProcessor()

    assert isinstance(
        processor.knowledge,
        KnowledgeModel,
    )


def test_capture_processor_relationship_tracker_uses_knowledge_model():
    processor = CaptureProcessor()

    assert (
        processor.relationship_tracker.knowledge
        is processor.knowledge
    )


def test_capture_processor_entity_tracker_uses_knowledge_model():
    processor = CaptureProcessor()

    assert (
        processor.entity_tracker.knowledge
        is processor.knowledge
    )


def test_capture_processor_uses_one_shared_knowledge_model():
    processor = CaptureProcessor()

    assert (
        processor.entity_tracker.knowledge
        is processor.relationship_tracker.knowledge
    )


def test_capture_processor_knowledge_model_starts_empty():
    processor = CaptureProcessor()

    assert processor.knowledge.entities() == []
    assert processor.knowledge.relationships() == []


def test_capture_processor_relationships_are_stored_in_knowledge_model():
    processor = CaptureProcessor()

    source = EntityRef(
        type="host",
        value="10.10.10.10",
    )

    target = EntityRef(
        type="host",
        value="10.10.10.20",
    )

    timestamp = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    processor.relationship_tracker.add(
        source=source,
        relation="connects_to",
        target=target,
        timestamp=timestamp,
    )

    relationships = processor.knowledge.relationships()

    assert len(relationships) == 1

    relationship = relationships[0]

    assert relationship.source == source
    assert relationship.relation == "connects_to"
    assert relationship.target == target
    assert relationship.first_seen == timestamp
    assert relationship.last_seen == timestamp