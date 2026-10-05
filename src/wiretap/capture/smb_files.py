from dataclasses import dataclass

from wiretap.models import (
    SMBFileOperation,
    SMBTransaction,
)


@dataclass(frozen=True)
class SMBFileHandle:
    file_id: str
    path: str


class SMBFileTracker:
    """
    Correlates SMB CREATE requests and responses into
    FileId -> path mappings.
    """

    def __init__(self) -> None:
        self._handles: dict[str, SMBFileHandle] = {}

    def add_transaction(
        self,
        transaction: SMBTransaction,
    ) -> None:
        request = transaction.request
        response = transaction.response

        if not isinstance(request, SMBFileOperation):
            return

        if not isinstance(response, SMBFileOperation):
            return

        if request.operation != "CREATE":
            return

        if response.operation != "CREATE":
            return

        if not request.path:
            return

        if not response.file_id:
            return

        self._handles[response.file_id] = SMBFileHandle(
            file_id=response.file_id,
            path=request.path,
        )

    def resolve(
        self,
        file_id: str,
    ) -> str | None:
        handle = self._handles.get(file_id)

        if handle is None:
            return None

        return handle.path

    def handles(self) -> list[SMBFileHandle]:
        return list(self._handles.values())

    def resolve_operation(
        self,
        operation: SMBFileOperation,
    ) -> SMBFileOperation:
        if not operation.file_id:
            return operation

        path = self.resolve(
            operation.file_id
        )

        if path is None:
            return operation

        operation.resolved_path = path

        return operation