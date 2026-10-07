from dataclasses import dataclass

from wiretap.models import (
    CertificateContext,
    EntityRef,
    HostContext,
    HostnameContext,
    IdentityContext,
    KnowledgeModel,
    PathContext,
    Relationship,
    ServiceContext,
    ShareContext,
)


@dataclass(frozen=True)
class QueryTraversal:
    """
    Result of a bounded relationship traversal.

    entities contains every entity encountered during traversal.

    relationships contains every relationship traversed while
    discovering those entities.
    """

    entities: list[EntityRef]
    relationships: list[Relationship]


@dataclass
class QueryEngine:
    """
    Analyst-facing query interface over the Wiretap knowledge model.

    QueryEngine does not store network intelligence itself. It delegates
    entity and context queries to KnowledgeModel and provides higher-level
    relationship traversal operations.
    """

    knowledge: KnowledgeModel

    def host(
        self,
        ip: str,
    ) -> HostContext | None:
        return self.knowledge.host_context(ip)

    def hostname(
        self,
        name: str,
    ) -> HostnameContext | None:
        return self.knowledge.hostname_context(name)

    def service(
        self,
        host_ip: str,
        port: int,
        protocol: str,
    ) -> ServiceContext | None:
        return self.knowledge.service_context(
            host_ip=host_ip,
            port=port,
            protocol=protocol,
        )

    def identity(
        self,
        identity: str,
    ) -> IdentityContext | None:
        return self.knowledge.identity_context(
            identity
        )

    def share(
        self,
        share: str,
    ) -> ShareContext | None:
        return self.knowledge.share_context(
            share
        )

    def path(
        self,
        path: str,
    ) -> PathContext | None:
        return self.knowledge.path_context(
            path
        )

    def certificate(
        self,
        fingerprint_sha256: str,
    ) -> CertificateContext | None:
        return self.knowledge.certificate_context(
            fingerprint_sha256
        )

    def related(
        self,
        entity: EntityRef,
        relation: str | None = None,
    ) -> list[EntityRef]:
        """
        Return entities targeted by relationships originating
        from the supplied entity.

        When relation is supplied, only that relationship type
        is followed.
        """
        relationships = self.knowledge.relationships_from(
            entity
        )

        if relation is not None:
            relationships = [
                relationship
                for relationship in relationships
                if relationship.relation == relation
            ]

        return [
            relationship.target
            for relationship in relationships
        ]

    def targets(
        self,
        source: EntityRef,
        relation: str | None = None,
    ) -> list[EntityRef]:
        """
        Return relationship targets originating from source.

        This is an explicit alias for related(), intended for
        query code where the source/target direction matters.
        """
        return self.related(
            entity=source,
            relation=relation,
        )

    def sources(
        self,
        target: EntityRef,
        relation: str | None = None,
    ) -> list[EntityRef]:
        """
        Return entities that have relationships pointing at target.

        When relation is supplied, only that relationship type
        is considered.
        """
        relationships = self.knowledge.relationships_to(
            target
        )

        if relation is not None:
            relationships = [
                relationship
                for relationship in relationships
                if relationship.relation == relation
            ]

        return [
            relationship.source
            for relationship in relationships
        ]

    def traverse(
        self,
        start: EntityRef,
        depth: int = 1,
        relation: str | None = None,
    ) -> QueryTraversal:
        """
        Perform a bounded outgoing relationship traversal.

        depth=1 returns entities directly connected to start.

        depth=2 follows relationships from those entities as well.

        Only outgoing relationships are followed. When relation is
        supplied, only relationships of that type are traversed.

        The start entity is always included in the result.

        Each entity and relationship appears at most once.
        """
        if depth < 0:
            raise ValueError(
                "depth must be greater than or equal to zero"
            )

        known_entities: dict[str, EntityRef] = {
            start.id: start
        }

        discovered_relationships: dict[
            str,
            Relationship,
        ] = {}

        frontier: list[EntityRef] = [
            start
        ]

        for _ in range(depth):
            next_frontier: list[EntityRef] = []

            for entity in frontier:
                relationships = (
                    self.knowledge.relationships_from(
                        entity
                    )
                )

                if relation is not None:
                    relationships = [
                        relationship
                        for relationship in relationships
                        if relationship.relation
                        == relation
                    ]

                for relationship in relationships:
                    discovered_relationships[
                        relationship.id
                    ] = relationship

                    target = relationship.target

                    if target.id in known_entities:
                        continue

                    known_entities[
                        target.id
                    ] = target

                    next_frontier.append(target)

            frontier = next_frontier

            if not frontier:
                break

        return QueryTraversal(
            entities=list(
                known_entities.values()
            ),
            relationships=list(
                discovered_relationships.values()
            ),
        )