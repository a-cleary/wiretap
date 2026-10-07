from wiretap.capture.flow import Flow
from wiretap.models import (
    EntityRef,
    Host,
    Hostname,
    KnowledgeModel,
    Service,
    TLSCertificate,
    TLSTransaction,
    SMBFileOperation,
    SMBSessionSetup,
    SMBTreeConnect,
)


class EntityTracker:
    """
    Compatibility layer around the central KnowledgeModel.

    The KnowledgeModel is the source of truth for entities and rich
    entity records. This class preserves the existing EntityTracker
    API while delegating storage to the knowledge model.
    """

    def __init__(
        self,
        knowledge: KnowledgeModel | None = None,
    ) -> None:
        self.knowledge = (
            knowledge
            if knowledge is not None
            else KnowledgeModel()
        )

    def add_flow(
        self,
        flow: Flow,
    ) -> None:
        self.knowledge.add_host(
            ip=flow.endpoint_a.ip,
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
        )

        self.knowledge.add_host(
            ip=flow.endpoint_b.ip,
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
        )

        if flow.responder is None:
            return

        if flow.responder.port is None:
            return

        self.knowledge.add_service(
            host_ip=flow.responder.ip,
            port=flow.responder.port,
            protocol=flow.protocol,
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
        )

    def add_dns_transaction(
        self,
        transaction,
    ) -> None:
        query = transaction.query

        self.knowledge.add_hostname(
            name=query.query,
            first_seen=query.timestamp,
            last_seen=transaction.timestamp,
        )

        for answer in transaction.answers:
            self.knowledge.add_hostname(
                name=answer.name,
                first_seen=query.timestamp,
                last_seen=transaction.timestamp,
            )

            if answer.record_type not in {
                "A",
                "AAAA",
            }:
                continue

            self.knowledge.add_host(
                ip=answer.value,
                first_seen=query.timestamp,
                last_seen=transaction.timestamp,
            )

    def add_tls_transaction(
        self,
        transaction: TLSTransaction,
    ) -> None:
        hello = transaction.client_hello

        if hello is None:
            return

        if hello.server_name is None:
            return

        self.knowledge.add_hostname(
            name=hello.server_name,
            first_seen=hello.timestamp,
            last_seen=hello.timestamp,
        )

    def add_tls_certificate(
        self,
        certificate: TLSCertificate,
    ) -> None:
        self.knowledge.add_certificate(
            fingerprint_sha256=(
                certificate.fingerprint_sha256
            ),
            timestamp=certificate.timestamp,
            certificate=certificate,
        )

    def add_smb_session_setup(
        self,
        observation: SMBSessionSetup,
    ) -> None:
        if not observation.username:
            return

        self.knowledge.add_identity(
            username=observation.username,
            domain=observation.domain,
        )

    def add_smb_tree_connect(
        self,
        observation: SMBTreeConnect,
    ) -> None:
        if not observation.share:
            return

        self.knowledge.add_share(
            share=observation.share
        )

    def add_smb_file_operation(
        self,
        observation: SMBFileOperation,
    ) -> None:
        if not observation.path:
            return

        self.knowledge.add_path(
            path=observation.path
        )

    def service_ref(
        self,
        service: Service,
    ) -> EntityRef:
        return EntityRef(
            type="service",
            value=(
                f"{service.protocol}/"
                f"{service.port}"
            ),
        )

    def host_ref(
        self,
        host: Host,
    ) -> EntityRef:
        return EntityRef(
            type="host",
            value=host.ip,
        )

    def hostname_ref(
        self,
        hostname: Hostname,
    ) -> EntityRef:
        return EntityRef(
            type="hostname",
            value=hostname.name,
        )

    def certificate_ref(
        self,
        certificate: TLSCertificate,
    ) -> EntityRef:
        return EntityRef(
            type="certificate",
            value=certificate.fingerprint_sha256,
        )

    def refs(self) -> list[EntityRef]:
        refs: list[EntityRef] = []

        refs.extend(
            self.host_ref(host)
            for host in self.knowledge.hosts()
        )

        refs.extend(
            self.hostname_ref(hostname)
            for hostname in self.knowledge.hostnames()
        )

        refs.extend(
            self.service_ref(service)
            for service in self.knowledge.services()
        )

        refs.extend(
            self.certificate_ref(certificate)
            for certificate
            in self.knowledge.certificates()
        )

        rich_entity_ids = {
            entity.id
            for entity in refs
        }

        refs.extend(
            entity
            for entity in self.knowledge.entities()
            if entity.id not in rich_entity_ids
        )

        return refs

    def hosts(self) -> list[Host]:
        return self.knowledge.hosts()

    def hostnames(self) -> list[Hostname]:
        return self.knowledge.hostnames()

    def services(self) -> list[Service]:
        return self.knowledge.services()

    def certificates(self) -> list[TLSCertificate]:
        return self.knowledge.certificates()