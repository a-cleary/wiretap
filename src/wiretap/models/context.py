from dataclasses import dataclass

from wiretap.models.host import Host
from wiretap.models.hostname import Hostname
from wiretap.models.relationship import Relationship
from wiretap.models.service import Service
from wiretap.models.tls import TLSCertificate


@dataclass(frozen=True)
class HostContext:
    """
    Analyst-facing context for a single host.

    This is a read-only view assembled from the KnowledgeModel.
    It contains the host itself plus the entities and relationships
    directly useful when investigating that host.
    """

    host: Host
    hostnames: list[Hostname]
    services: list[Service]
    related_hosts: list[Host]
    incoming_relationships: list[Relationship]
    outgoing_relationships: list[Relationship]


@dataclass(frozen=True)
class HostnameContext:
    """
    Analyst-facing context for a hostname.

    The hostname can be associated with hosts through relationships
    such as:

        hostname --resolves_to--> host
    """

    hostname: Hostname
    resolved_hosts: list[Host]
    incoming_relationships: list[Relationship]
    outgoing_relationships: list[Relationship]


@dataclass(frozen=True)
class ServiceContext:
    """
    Analyst-facing context for a network service.

    A service is represented by a host, port, and protocol.
    """

    service: Service
    host: Host | None
    incoming_relationships: list[Relationship]
    outgoing_relationships: list[Relationship]


@dataclass(frozen=True)
class IdentityContext:
    """
    Analyst-facing context for an observed identity.

    Identity records are currently represented as generic entities,
    so the context is relationship-centric.
    """

    identity: str
    incoming_relationships: list[Relationship]
    outgoing_relationships: list[Relationship]


@dataclass(frozen=True)
class ShareContext:
    """
    Analyst-facing context for an SMB share.

    Share records are currently represented as generic entities,
    so the context is relationship-centric.
    """

    share: str
    incoming_relationships: list[Relationship]
    outgoing_relationships: list[Relationship]


@dataclass(frozen=True)
class PathContext:
    """
    Analyst-facing context for a filesystem path.

    Path records are currently represented as generic entities,
    so the context is relationship-centric.
    """

    path: str
    incoming_relationships: list[Relationship]
    outgoing_relationships: list[Relationship]


@dataclass(frozen=True)
class CertificateContext:
    """
    Analyst-facing context for a TLS certificate.
    """

    certificate: TLSCertificate
    incoming_relationships: list[Relationship]
    outgoing_relationships: list[Relationship]