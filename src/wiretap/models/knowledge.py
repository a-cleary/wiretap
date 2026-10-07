from dataclasses import dataclass, field
from datetime import datetime

from wiretap.models.context import (
    CertificateContext,
    HostContext,
    HostnameContext,
    IdentityContext,
    PathContext,
    ServiceContext,
    ShareContext,
)
from wiretap.models.entity import EntityRef
from wiretap.models.host import Host
from wiretap.models.hostname import Hostname
from wiretap.models.relationship import Relationship
from wiretap.models.service import Service
from wiretap.models.tls import TLSCertificate


@dataclass
class KnowledgeModel:
    """
    In-memory representation of network context discovered from
    one or more observations.

    The knowledge model does not parse packets and does not make
    security judgments. It stores entities, rich entity records,
    and the relationships observed between them.
    """

    _entities: dict[str, EntityRef] = field(
        default_factory=dict
    )

    _relationships: dict[
        str,
        Relationship,
    ] = field(
        default_factory=dict
    )

    _hosts: dict[str, Host] = field(
        default_factory=dict
    )

    _hostnames: dict[str, Hostname] = field(
        default_factory=dict
    )

    _services: dict[
        tuple[str, int, str],
        Service,
    ] = field(
        default_factory=dict
    )

    _certificates: dict[
        str,
        TLSCertificate,
    ] = field(
        default_factory=dict
    )

    def add_entity(
        self,
        entity: EntityRef,
    ) -> EntityRef:
        """
        Add an entity to the model.

        Existing entities are returned unchanged.
        """
        existing = self._entities.get(entity.id)

        if existing is not None:
            return existing

        self._entities[entity.id] = entity

        return entity

    def add_identity(
        self,
        username: str,
        domain: str | None = None,
    ) -> EntityRef:
        """
        Add an identity entity.

        When a domain is supplied, the identity is represented as:

            DOMAIN\\username
        """
        identity = username

        if domain:
            identity = (
                f"{domain}\\"
                f"{username}"
            )

        return self.add_entity(
            EntityRef(
                type="identity",
                value=identity,
            )
        )

    def add_share(
        self,
        share: str,
    ) -> EntityRef:
        """
        Add an SMB share entity.
        """
        return self.add_entity(
            EntityRef(
                type="share",
                value=share,
            )
        )

    def add_path(
        self,
        path: str,
    ) -> EntityRef:
        """
        Add a filesystem path entity.
        """
        return self.add_entity(
            EntityRef(
                type="path",
                value=path,
            )
        )

    def add_host(
        self,
        ip: str,
        first_seen: datetime,
        last_seen: datetime,
    ) -> Host:
        """
        Add or update a host.

        The corresponding host EntityRef is registered automatically.
        """
        self.add_entity(
            EntityRef(
                type="host",
                value=ip,
            )
        )

        existing = self._hosts.get(ip)

        if existing is None:
            host = Host(
                ip=ip,
                first_seen=first_seen,
                last_seen=last_seen,
            )

            self._hosts[ip] = host

            return host

        existing.first_seen = min(
            existing.first_seen,
            first_seen,
        )

        existing.last_seen = max(
            existing.last_seen,
            last_seen,
        )

        return existing

    def add_hostname(
        self,
        name: str,
        first_seen: datetime,
        last_seen: datetime,
    ) -> Hostname:
        """
        Add or update a hostname.

        The corresponding hostname EntityRef is registered automatically.
        """
        self.add_entity(
            EntityRef(
                type="hostname",
                value=name,
            )
        )

        existing = self._hostnames.get(name)

        if existing is None:
            hostname = Hostname(
                name=name,
                first_seen=first_seen,
                last_seen=last_seen,
            )

            self._hostnames[name] = hostname

            return hostname

        existing.first_seen = min(
            existing.first_seen,
            first_seen,
        )

        existing.last_seen = max(
            existing.last_seen,
            last_seen,
        )

        return existing

    def add_service(
        self,
        host_ip: str,
        port: int,
        protocol: str,
        first_seen: datetime,
        last_seen: datetime,
    ) -> Service:
        """
        Add or update a service.

        The corresponding service EntityRef is registered automatically.
        """
        service_ref = EntityRef(
            type="service",
            value=(
                f"{protocol}/"
                f"{port}"
            ),
        )

        self.add_entity(service_ref)

        key = (
            host_ip,
            port,
            protocol,
        )

        existing = self._services.get(key)

        if existing is None:
            service = Service(
                host_ip=host_ip,
                port=port,
                protocol=protocol,
                first_seen=first_seen,
                last_seen=last_seen,
            )

            self._services[key] = service

            return service

        existing.first_seen = min(
            existing.first_seen,
            first_seen,
        )

        existing.last_seen = max(
            existing.last_seen,
            last_seen,
        )

        return existing

    def add_certificate(
        self,
        fingerprint_sha256: str,
        timestamp: datetime,
        *,
        certificate: TLSCertificate | None = None,
    ) -> TLSCertificate:
        """
        Add or update a TLS certificate.

        The corresponding certificate EntityRef is registered automatically.

        If a complete TLSCertificate is supplied, it is stored. When multiple
        observations of the same certificate exist, the earliest observation
        is retained.
        """
        self.add_entity(
            EntityRef(
                type="certificate",
                value=fingerprint_sha256,
            )
        )

        if certificate is None:
            certificate = TLSCertificate(
                timestamp=timestamp,
                source_ip="",
                source_port=None,
                destination_ip="",
                destination_port=None,
                fingerprint_sha256=fingerprint_sha256,
                subject=None,
                issuer=None,
                serial_number=None,
                not_before=None,
                not_after=None,
                subject_alt_names=[],
            )

        existing = self._certificates.get(
            fingerprint_sha256
        )

        if existing is None:
            self._certificates[
                fingerprint_sha256
            ] = certificate

            return certificate

        if existing.timestamp > certificate.timestamp:
            self._certificates[
                fingerprint_sha256
            ] = certificate

            return certificate

        return existing

    def add_relationship(
        self,
        source: EntityRef,
        relation: str,
        target: EntityRef,
        timestamp: datetime,
    ) -> Relationship:
        """
        Add or update a relationship.

        Repeated observations of the same relationship are
        collapsed into one relationship while preserving the
        first and last time it was observed.
        """
        self.add_entity(source)
        self.add_entity(target)

        relationship = Relationship(
            source=source,
            relation=relation,
            target=target,
            first_seen=timestamp,
            last_seen=timestamp,
        )

        existing = self._relationships.get(
            relationship.id
        )

        if existing is None:
            self._relationships[
                relationship.id
            ] = relationship

            return relationship

        updated = Relationship(
            source=existing.source,
            relation=existing.relation,
            target=existing.target,
            first_seen=min(
                existing.first_seen,
                timestamp,
            ),
            last_seen=max(
                existing.last_seen,
                timestamp,
            ),
        )

        self._relationships[
            updated.id
        ] = updated

        return updated

    def entity(
        self,
        entity_id: str,
    ) -> EntityRef | None:
        return self._entities.get(entity_id)

    def entities(
        self,
    ) -> list[EntityRef]:
        return list(
            self._entities.values()
        )

    def entities_by_type(
        self,
        entity_type: str,
    ) -> list[EntityRef]:
        return [
            entity
            for entity in self._entities.values()
            if entity.type == entity_type
        ]

    def hosts(
        self,
    ) -> list[Host]:
        return list(
            self._hosts.values()
        )

    def hostnames(
        self,
    ) -> list[Hostname]:
        return list(
            self._hostnames.values()
        )

    def services(
        self,
    ) -> list[Service]:
        return list(
            self._services.values()
        )

    def certificates(
        self,
    ) -> list[TLSCertificate]:
        return list(
            self._certificates.values()
        )

    def host(
        self,
        ip: str,
    ) -> Host | None:
        return self._hosts.get(ip)

    def hostname(
        self,
        name: str,
    ) -> Hostname | None:
        return self._hostnames.get(name)

    def service(
        self,
        host_ip: str,
        port: int,
        protocol: str,
    ) -> Service | None:
        return self._services.get(
            (
                host_ip,
                port,
                protocol,
            )
        )

    def related_hosts(
        self,
        ip: str,
        relation: str | None = None,
    ) -> list[Host]:
        """
        Return hosts related to the supplied host.

        Only outgoing relationships are considered.
        """
        source = EntityRef(
            type="host",
            value=ip,
        )

        relationships = self.relationships_from(
            source
        )

        if relation is not None:
            relationships = [
                relationship
                for relationship in relationships
                if relationship.relation == relation
            ]

        hosts_by_ip: dict[str, Host] = {}

        for relationship in relationships:
            if relationship.target.type != "host":
                continue

            host = self.host(
                relationship.target.value
            )

            if host is not None:
                hosts_by_ip[host.ip] = host

        return list(
            hosts_by_ip.values()
        )

    def services_for_host(
        self,
        ip: str,
    ) -> list[Service]:
        return [
            service
            for service in self._services.values()
            if service.host_ip == ip
        ]

    def hostnames_for_host(
        self,
        ip: str,
    ) -> list[Hostname]:
        target = EntityRef(
            type="host",
            value=ip,
        )

        relationships = self.relationships_to(
            target
        )

        hostnames: list[Hostname] = []

        for relationship in relationships:
            if relationship.source.type != "hostname":
                continue

            hostname = self.hostname(
                relationship.source.value
            )

            if hostname is not None:
                hostnames.append(hostname)

        return hostnames

    def host_context(
        self,
        ip: str,
    ) -> HostContext | None:
        """
        Return an analyst-facing context view for a host.

        Returns None when the host is unknown.
        """
        host = self.host(ip)

        if host is None:
            return None

        host_ref = EntityRef(
            type="host",
            value=ip,
        )

        return HostContext(
            host=host,
            hostnames=self.hostnames_for_host(ip),
            services=self.services_for_host(ip),
            related_hosts=self.related_hosts(ip),
            incoming_relationships=self.relationships_to(
                host_ref
            ),
            outgoing_relationships=self.relationships_from(
                host_ref
            ),
        )

    def hostname_context(
        self,
        name: str,
    ) -> HostnameContext | None:
        """
        Return an analyst-facing context view for a hostname.

        Returns None when the hostname is unknown.
        """
        hostname = self.hostname(name)

        if hostname is None:
            return None

        hostname_ref = EntityRef(
            type="hostname",
            value=name,
        )

        incoming_relationships = (
            self.relationships_to(
                hostname_ref
            )
        )

        outgoing_relationships = (
            self.relationships_from(
                hostname_ref
            )
        )

        resolved_hosts: list[Host] = []

        for relationship in outgoing_relationships:
            if (
                relationship.relation
                != "resolves_to"
            ):
                continue

            if relationship.target.type != "host":
                continue

            host = self.host(
                relationship.target.value
            )

            if host is not None:
                resolved_hosts.append(host)

        return HostnameContext(
            hostname=hostname,
            resolved_hosts=resolved_hosts,
            incoming_relationships=(
                incoming_relationships
            ),
            outgoing_relationships=(
                outgoing_relationships
            ),
        )

    def service_context(
        self,
        host_ip: str,
        port: int,
        protocol: str,
    ) -> ServiceContext | None:
        """
        Return an analyst-facing context view for a service.

        Returns None when the service is unknown.
        """
        service = self.service(
            host_ip=host_ip,
            port=port,
            protocol=protocol,
        )

        if service is None:
            return None

        service_ref = EntityRef(
            type="service",
            value=(
                f"{protocol}/"
                f"{port}"
            ),
        )

        return ServiceContext(
            service=service,
            host=self.host(host_ip),
            incoming_relationships=(
                self.relationships_to(
                    service_ref
                )
            ),
            outgoing_relationships=(
                self.relationships_from(
                    service_ref
                )
            ),
        )

    def _entity_context_relationships(
        self,
        entity_type: str,
        value: str,
    ) -> tuple[
        list[Relationship],
        list[Relationship],
    ]:
        """
        Return incoming and outgoing relationships for a generic entity.
        """
        entity = EntityRef(
            type=entity_type,
            value=value,
        )

        return (
            self.relationships_to(entity),
            self.relationships_from(entity),
        )

    def identity_context(
        self,
        identity: str,
    ) -> IdentityContext | None:
        """
        Return an analyst-facing context view for an identity.

        Returns None when the identity is unknown.
        """
        entity = self.entity(
            f"identity:{identity}"
        )

        if entity is None:
            return None

        (
            incoming_relationships,
            outgoing_relationships,
        ) = self._entity_context_relationships(
            "identity",
            identity,
        )

        return IdentityContext(
            identity=identity,
            incoming_relationships=(
                incoming_relationships
            ),
            outgoing_relationships=(
                outgoing_relationships
            ),
        )

    def share_context(
        self,
        share: str,
    ) -> ShareContext | None:
        """
        Return an analyst-facing context view for an SMB share.

        Returns None when the share is unknown.
        """
        entity = self.entity(
            f"share:{share}"
        )

        if entity is None:
            return None

        (
            incoming_relationships,
            outgoing_relationships,
        ) = self._entity_context_relationships(
            "share",
            share,
        )

        return ShareContext(
            share=share,
            incoming_relationships=(
                incoming_relationships
            ),
            outgoing_relationships=(
                outgoing_relationships
            ),
        )

    def path_context(
        self,
        path: str,
    ) -> PathContext | None:
        """
        Return an analyst-facing context view for a filesystem path.

        Returns None when the path is unknown.
        """
        entity = self.entity(
            f"path:{path}"
        )

        if entity is None:
            return None

        (
            incoming_relationships,
            outgoing_relationships,
        ) = self._entity_context_relationships(
            "path",
            path,
        )

        return PathContext(
            path=path,
            incoming_relationships=(
                incoming_relationships
            ),
            outgoing_relationships=(
                outgoing_relationships
            ),
        )

    def certificate_context(
        self,
        fingerprint_sha256: str,
    ) -> CertificateContext | None:
        """
        Return an analyst-facing context view for a TLS certificate.

        Returns None when the certificate is unknown.
        """
        certificate = self._certificates.get(
            fingerprint_sha256
        )

        if certificate is None:
            return None

        (
            incoming_relationships,
            outgoing_relationships,
        ) = self._entity_context_relationships(
            "certificate",
            fingerprint_sha256,
        )

        return CertificateContext(
            certificate=certificate,
            incoming_relationships=(
                incoming_relationships
            ),
            outgoing_relationships=(
                outgoing_relationships
            ),
        )

    def relationship(
        self,
        relationship_id: str,
    ) -> Relationship | None:
        return self._relationships.get(
            relationship_id
        )

    def relationships(
        self,
    ) -> list[Relationship]:
        return list(
            self._relationships.values()
        )

    def relationships_from(
        self,
        source: EntityRef,
    ) -> list[Relationship]:
        return [
            relationship
            for relationship
            in self._relationships.values()
            if relationship.source == source
        ]

    def relationships_to(
        self,
        target: EntityRef,
    ) -> list[Relationship]:
        return [
            relationship
            for relationship
            in self._relationships.values()
            if relationship.target == target
        ]

    def relationships_by_type(
        self,
        relation: str,
    ) -> list[Relationship]:
        return [
            relationship
            for relationship
            in self._relationships.values()
            if relationship.relation == relation
        ]

    def clear(self) -> None:
        self._entities.clear()
        self._relationships.clear()
        self._hosts.clear()
        self._hostnames.clear()
        self._services.clear()
        self._certificates.clear()