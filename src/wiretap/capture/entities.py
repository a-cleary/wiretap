from wiretap.capture.flow import Flow
from wiretap.models import (
    EntityRef,
    Host,
    Hostname,
    Service,
    TLSClientHello,
    TLSTransaction,
)


class EntityTracker:
    def __init__(self) -> None:
        self._hosts: dict[str, Host] = {}

        self._hostnames: dict[str, Hostname] = {}

        self._services: dict[
            tuple[str, int, str],
            Service,
        ] = {}

    def add_flow(self, flow: Flow) -> None:
        self._add_host(
            flow.endpoint_a.ip,
            flow.first_seen,
            flow.last_seen,
        )

        self._add_host(
            flow.endpoint_b.ip,
            flow.first_seen,
            flow.last_seen,
        )

        if flow.responder is None:
            return

        if flow.responder.port is None:
            return

        self._add_service(
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

        self._add_hostname(
            query.query,
            query.timestamp,
            transaction.timestamp,
        )

        for answer in transaction.answers:
            self._add_hostname(
                answer.name,
                query.timestamp,
                transaction.timestamp,
            )

            if answer.record_type not in {
                "A",
                "AAAA",
            }:
                continue

            self._add_host(
                answer.value,
                query.timestamp,
                transaction.timestamp,
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

        self._add_hostname(
            hello.server_name,
            hello.timestamp,
            hello.timestamp,
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

    def _add_host(
        self,
        ip: str,
        first_seen,
        last_seen,
    ) -> None:
        host = self._hosts.get(ip)

        if host is None:
            self._hosts[ip] = Host(
                ip=ip,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            return

        host.first_seen = min(
            host.first_seen,
            first_seen,
        )

        host.last_seen = max(
            host.last_seen,
            last_seen,
        )

    def _add_hostname(
        self,
        name: str,
        first_seen,
        last_seen,
    ) -> None:
        hostname = self._hostnames.get(name)

        if hostname is None:
            self._hostnames[name] = Hostname(
                name=name,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            return

        hostname.first_seen = min(
            hostname.first_seen,
            first_seen,
        )

        hostname.last_seen = max(
            hostname.last_seen,
            last_seen,
        )

    def _add_service(
        self,
        host_ip: str,
        port: int,
        protocol: str,
        first_seen,
        last_seen,
    ) -> None:
        key = (
            host_ip,
            port,
            protocol,
        )

        service = self._services.get(key)

        if service is None:
            self._services[key] = Service(
                host_ip=host_ip,
                port=port,
                protocol=protocol,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            return

        service.first_seen = min(
            service.first_seen,
            first_seen,
        )

        service.last_seen = max(
            service.last_seen,
            last_seen,
        )

    def hosts(self) -> list[Host]:
        return list(self._hosts.values())

    def hostnames(self) -> list[Hostname]:
        return list(self._hostnames.values())

    def services(self) -> list[Service]:
        return list(self._services.values())