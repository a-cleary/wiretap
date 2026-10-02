from datetime import datetime, timezone

from wiretap.capture.smb_files import (
    SMBFileTracker,
)
from wiretap.models import (
    SMBFileOperation,
    SMBTransaction,
)


def timestamp():
    return datetime.fromtimestamp(
        1767268801.0,
        tz=timezone.utc,
    )


def test_create_transaction_maps_file_id_to_path():
    request = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.42",
        source_port=49153,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="CREATE",
        message_type="request",
        message_id=10,
        session_id=123,
        tree_id=456,
        operation="CREATE",
        path=r"\Temp\payload.exe",
    )

    response = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.30",
        source_port=445,
        destination_ip="10.10.10.42",
        destination_port=49153,
        version="SMB3",
        command="CREATE",
        message_type="response",
        message_id=10,
        session_id=123,
        tree_id=456,
        operation="CREATE",
        file_id="00112233445566778899aabbccddeeff",
    )

    transaction = SMBTransaction(
        request=request,
        response=response,
    )

    tracker = SMBFileTracker()

    tracker.add_transaction(transaction)

    assert tracker.resolve(
        "00112233445566778899aabbccddeeff"
    ) == r"\Temp\payload.exe"


def test_unknown_file_id_returns_none():
    tracker = SMBFileTracker()

    assert tracker.resolve(
        "00112233445566778899aabbccddeeff"
    ) is None


def test_create_without_path_is_ignored():
    request = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.42",
        source_port=49153,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="CREATE",
        message_type="request",
        message_id=10,
        operation="CREATE",
        path=None,
    )

    response = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.30",
        source_port=445,
        destination_ip="10.10.10.42",
        destination_port=49153,
        version="SMB3",
        command="CREATE",
        message_type="response",
        message_id=10,
        operation="CREATE",
        file_id="00112233445566778899aabbccddeeff",
    )

    tracker = SMBFileTracker()

    tracker.add_transaction(
        SMBTransaction(
            request=request,
            response=response,
        )
    )

    assert tracker.resolve(
        "00112233445566778899aabbccddeeff"
    ) is None


def test_non_create_transaction_is_ignored():
    request = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.42",
        source_port=49153,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="READ",
        message_type="request",
        message_id=11,
        operation="READ",
        file_id="00112233445566778899aabbccddeeff",
    )

    response = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.30",
        source_port=445,
        destination_ip="10.10.10.42",
        destination_port=49153,
        version="SMB3",
        command="READ",
        message_type="response",
        message_id=11,
        operation="READ",
    )

    tracker = SMBFileTracker()

    tracker.add_transaction(
        SMBTransaction(
            request=request,
            response=response,
        )
    )

    assert tracker.handles() == []


def test_file_operation_resolves_file_id_to_path():
    tracker = SMBFileTracker()

    request = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.42",
        source_port=49153,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="CREATE",
        message_type="request",
        message_id=10,
        operation="CREATE",
        path=r"\Temp\payload.exe",
    )

    response = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.30",
        source_port=445,
        destination_ip="10.10.10.42",
        destination_port=49153,
        version="SMB3",
        command="CREATE",
        message_type="response",
        message_id=10,
        operation="CREATE",
        file_id="00112233445566778899aabbccddeeff",
    )

    tracker.add_transaction(
        SMBTransaction(
            request=request,
            response=response,
        )
    )

    read = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.42",
        source_port=49153,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="READ",
        message_type="request",
        message_id=11,
        operation="READ",
        file_id="00112233445566778899aabbccddeeff",
    )

    resolved = tracker.resolve_operation(read)

    assert resolved.file_id == (
        "00112233445566778899aabbccddeeff"
    )

    assert resolved.resolved_path == (
        r"\Temp\payload.exe"
    )


def test_unknown_file_id_does_not_resolve_operation():
    tracker = SMBFileTracker()

    operation = SMBFileOperation(
        timestamp=timestamp(),
        source_ip="10.10.10.42",
        source_port=49153,
        destination_ip="10.10.10.30",
        destination_port=445,
        version="SMB3",
        command="READ",
        message_type="request",
        message_id=11,
        operation="READ",
        file_id="deadbeef",
    )

    resolved = tracker.resolve_operation(operation)

    assert resolved.resolved_path is None