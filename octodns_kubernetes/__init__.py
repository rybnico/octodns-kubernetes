from ipaddress import IPv4Address, IPv6Address, ip_address
from logging import getLogger

from kubernetes import client, config

from octodns.record import Record
from octodns.source.base import BaseSource

__VERSION__ = '0.0.1'


class KubernetesSource(BaseSource):
    SUPPORTS = ('A', 'AAAA', 'CNAME')
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False

    DEFAULT_HOSTNAME_ANNOTATIONS = ['octodns-kubernetes.rybni.co/hostname']
    DEFAULT_TTL_ANNOTATIONS = ['octodns-kubernetes.rybni.co/ttl']
    DEFAULT_TARGET_ANNOTATIONS = ['octodns-kubernetes.rybni.co/target']

    def __init__(
        self,
        id,
        types=('A', 'AAAA'),
        ttl=300,
        hostnameAnnotations=DEFAULT_HOSTNAME_ANNOTATIONS,
        ttlAnnotations=DEFAULT_TTL_ANNOTATIONS,
        targetAnnotations=DEFAULT_TARGET_ANNOTATIONS,
    ):
        self.log = getLogger('KubernetesSource[{}]'.format(id))
        self.log.debug('__init__: id=%s, types=%s, ttl=%d', id, types, ttl)
        super().__init__(id)
        self.types = types
        self.ttl = ttl
        self.hostnameAnnotations = hostnameAnnotations
        self.ttlAnnotations = ttlAnnotations
        self.targetAnnotations = targetAnnotations
        config.load_config()
        self.networking_v1_api = client.NetworkingV1Api()
        self.ingresses = (
            self.networking_v1_api.list_ingress_for_all_namespaces().items
        )

    def _add_record(
        self, zone, name, ttl, type, values=None, value=None, lenient=False
    ):
        try:
            record = Record.new(
                zone,
                name,
                {'ttl': ttl, 'type': type, 'values': values, 'value': value},
                source=self,
                lenient=lenient,
            )
            zone.add_record(record, lenient=lenient)
        except Exception as e:
            if lenient:
                self.log.error(e)
            else:
                raise e

    def _get_first_matching_annotation(self, k8s_resource, annotations):
        try:
            for annotationToFind in annotations:
                for (
                    annotation,
                    value,
                ) in k8s_resource.metadata.annotations.items():
                    if annotation == annotationToFind:
                        return value
        except AttributeError:
            return None

    def _is_ipaddress(self, ip_string):
        try:
            ip_address(ip_string)
            return True
        except ValueError:
            return False

    def _get_targets_from_ingress(self, ingress):
        unknown_targets = []  # unknown if IPv4, IPv6 or Hostname
        ip_targets = []  # either IPv4 or IPv6
        hostname_targets = []  # hostnames

        if targetAnnotation := self._get_first_matching_annotation(
            ingress, self.targetAnnotations
        ):
            # If target annotation is set, use targets from annotation
            unknown_targets = targetAnnotation.split(",")
        else:
            # If target annotation is not set, use targets from ingress statuses
            try:
                ingress_statuses = ingress.status.load_balancer.ingress
                ip_targets = [v.ip for v in ingress_statuses if v.ip]
                hostname_targets = [
                    v.hostname for v in ingress_statuses if v.hostname
                ]
            except AttributeError:
                pass  # pass to return empty lists if wether the target annotation nor the ingress status is set
        ipv4_targets = [
            v
            for v in ip_targets + unknown_targets
            if self._is_ipaddress(v) and type(ip_address(v)) is IPv4Address
        ]
        ipv6_targets = [
            v
            for v in ip_targets + unknown_targets
            if self._is_ipaddress(v) and type(ip_address(v)) is IPv6Address
        ]
        cname_targets = [
            v
            for v in hostname_targets + unknown_targets
            if not self._is_ipaddress(v)
            or (
                type(ip_address(v)) is not IPv4Address
                and type(ip_address(v)) is not IPv6Address
            )
        ]
        return ipv4_targets, ipv6_targets, cname_targets

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: zone=%s', zone.name)

        if target:
            raise NotImplementedError(
                'KubernetesSource is a source only provider and does not support target mode'
            )

        for ingress in self.ingresses:
            if (
                annotationHostnames := self._get_first_matching_annotation(
                    ingress, self.hostnameAnnotations
                )
            ) is not None:
                ttl = int(
                    self._get_first_matching_annotation(
                        ingress, self.ttlAnnotations
                    )
                    or self.ttl
                )

                # Cast to set to remove duplicates
                for hostname in set(annotationHostnames.split(",")):
                    zoneWithoutDot = zone.name.rstrip('.')
                    if hostname.endswith(zoneWithoutDot):
                        name = hostname.removesuffix('.' + zoneWithoutDot)

                        (
                            ipv4_targets,
                            ipv6_targets,
                            cname_targets,
                        ) = self._get_targets_from_ingress(ingress)

                        if len(ipv4_targets) > 0:
                            self._add_record(
                                zone=zone,
                                name=name,
                                ttl=ttl,
                                type="A",
                                values=ipv4_targets,
                                lenient=lenient,
                            )
                        if len(ipv6_targets) > 0:
                            self._add_record(
                                zone=zone,
                                name=name,
                                ttl=ttl,
                                type="AAAA",
                                values=ipv6_targets,
                                lenient=lenient,
                            )
                        if (
                            len(cname_targets) > 0
                            and len(ipv4_targets) + len(ipv6_targets) > 0
                        ):
                            self.log.error(
                                "Both CNAME and A/AAAA records found in Ingress %s, prefering A/AAAA records",
                                ingress.metadata.name,
                            )
                        elif len(cname_targets) > 0:
                            if len(cname_targets) > 1:
                                self.log.error(
                                    "More than one CNAME record found in Ingress %s, prefering first record %s",
                                    ingress.metadata.name,
                                    cname_targets[0],
                                )
                            cname_value = cname_targets[0].rstrip('.') + '.'
                            self._add_record(
                                zone=zone,
                                name=name,
                                ttl=ttl,
                                type='CNAME',
                                value=cname_value,
                                lenient=lenient,
                            )
        self.log.debug('populate:   found %d records', len(zone.records))
