from dataclasses import dataclass

from wiretap.models import (
    SMBFileOperation,
    SMBSessionSetup,
    SMBTreeConnect,
)


@dataclass(frozen=True)
class SMBSessionContext:
    session_id: int
    identity: str | None = None


@dataclass(frozen=True)
class SMBTreeContext:
    session_id: int
    tree_id: int
    share: str | None = None


class SMBContextTracker:
    """
    Tracks SMB session and tree context so file operations
    can be associated with an authenticated identity and share.
    """

    def __init__(self) -> None:
        self._sessions: dict[
            int,
            SMBSessionContext,
        ] = {}

        self._trees: dict[
            tuple[int, int],
            SMBTreeContext,
        ] = {}

    def add_session_setup(
        self,
        observation: SMBSessionSetup,
    ) -> None:
        if observation.session_id is None:
            return

        identity = observation.username

        if identity and observation.domain:
            identity = (
                f"{observation.domain}\\"
                f"{identity}"
            )

        self._sessions[
            observation.session_id
        ] = SMBSessionContext(
            session_id=observation.session_id,
            identity=identity,
        )

    def add_tree_connect(
        self,
        observation: SMBTreeConnect,
    ) -> None:
        if observation.session_id is None:
            return

        if observation.tree_id is None:
            return

        key = (
            observation.session_id,
            observation.tree_id,
        )

        self._trees[key] = SMBTreeContext(
            session_id=observation.session_id,
            tree_id=observation.tree_id,
            share=observation.share,
        )

    def session(
        self,
        session_id: int,
    ) -> SMBSessionContext | None:
        return self._sessions.get(session_id)

    def tree(
        self,
        session_id: int,
        tree_id: int,
    ) -> SMBTreeContext | None:
        return self._trees.get(
            (
                session_id,
                tree_id,
            )
        )

    def resolve_operation(
        self,
        operation: SMBFileOperation,
    ) -> SMBFileOperation:
        if operation.session_id is None:
            return operation

        session = self.session(
            operation.session_id
        )

        if session is not None:
            operation.identity = session.identity

        if operation.tree_id is not None:
            tree = self.tree(
                operation.session_id,
                operation.tree_id,
            )

            if tree is not None:
                operation.share = tree.share

        return operation

    def sessions(
        self,
    ) -> list[SMBSessionContext]:
        return list(
            self._sessions.values()
        )

    def trees(
        self,
    ) -> list[SMBTreeContext]:
        return list(
            self._trees.values()
        )