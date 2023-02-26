from unittest import TestCase
from unittest.mock import patch

from kubernetes import client

from octodns.record import AaaaRecord, ARecord, CnameRecord, ValidationError
from octodns.zone import DuplicateRecordException, Zone

from octodns_kubernetes import KubernetesSource


class MockClient(object):
    def __init__(self, ingresses):
        self.ingresses = ingresses

    def list_ingress_for_all_namespaces(self):
        return self.ingresses


class TestKubernetesSource(TestCase):
    @patch('kubernetes.client.NetworkingV1Api')
    @patch('kubernetes.config.load_kube_config')
    def test_complete(self, mock_config, mock_client):
        mock_config.return_value = None
        mock_client.return_value = MockClient(
            client.V1IngressList(
                items=[
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='valid_v4',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'v4.example.com',
                                KubernetesSource.DEFAULT_TTL_ANNOTATIONS[
                                    0
                                ]: '301',
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(ip='1.1.1.1'),
                                    client.V1LoadBalancerIngress(ip='2.2.2.2'),
                                ]
                            )
                        ),
                    ),
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='valid_v6',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'v6.example.com',
                                KubernetesSource.DEFAULT_TTL_ANNOTATIONS[
                                    0
                                ]: '302',
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        ip='1:1:1:1:1:1:1:1'
                                    ),
                                    client.V1LoadBalancerIngress(
                                        ip='2:2:2:2:2:2:2:2'
                                    ),
                                ]
                            )
                        ),
                    ),
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='multiple_cnames_valid',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'cname.example.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        hostname='cname.test.com'
                                    ),
                                    client.V1LoadBalancerIngress(
                                        hostname='cname2.test.com'
                                    ),
                                ]
                            )
                        ),
                    ),
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='valid_v6_target',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'v6_target.example.com',
                                KubernetesSource.DEFAULT_TARGET_ANNOTATIONS[
                                    0
                                ]: '3:3:3:3:3:3:3:3',
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        ip='1:1:1:1:1:1:1:1'
                                    ),
                                    client.V1LoadBalancerIngress(
                                        ip='2:2:2:2:2:2:2:2'
                                    ),
                                ]
                            )
                        ),
                    ),
                ]
            )
        )
        zone = Zone('example.com.', [])
        KubernetesSource('kubernetes', ttl=303).populate(zone)
        self.assertEqual(4, len(zone.records))
        records = sorted(list(zone.records))

        ipv4_records = [record for record in records if record.name == 'v4']
        self.assertEqual(1, len(ipv4_records))
        ipv4_record = ipv4_records[0]
        self.assertEqual(ipv4_record.name, 'v4')
        self.assertEqual(ipv4_record.ttl, 301)
        self.assertEqual(type(ipv4_record), ARecord)
        self.assertEqual(ipv4_record.values, ['1.1.1.1', '2.2.2.2'])

        ipv6_records = [record for record in records if record.name == 'v6']
        self.assertEqual(1, len(ipv6_records))
        ipv6_record = ipv6_records[0]
        self.assertEqual(ipv6_record.name, 'v6')
        self.assertEqual(ipv6_record.ttl, 302)
        self.assertEqual(type(ipv6_record), AaaaRecord)
        self.assertEqual(
            ipv6_record.values, ['1:1:1:1:1:1:1:1', '2:2:2:2:2:2:2:2']
        )

        cname_records = [record for record in records if record.name == 'cname']
        self.assertEqual(1, len(cname_records))
        cname_record = cname_records[0]
        self.assertEqual(cname_record.name, 'cname')
        self.assertEqual(cname_record.ttl, 303)
        self.assertEqual(type(cname_record), CnameRecord)
        self.assertIn(
            cname_record.value, ['cname.test.com.', 'cname2.test.com.']
        )

        v6_target_records = [
            record for record in records if record.name == 'v6_target'
        ]
        self.assertEqual(1, len(v6_target_records))
        v6_target_record = v6_target_records[0]
        self.assertEqual(v6_target_record.name, 'v6_target')
        self.assertEqual(v6_target_record.ttl, 303)
        self.assertEqual(type(v6_target_record), AaaaRecord)
        self.assertIn('3:3:3:3:3:3:3:3', v6_target_record.values)

    @patch('kubernetes.client.NetworkingV1Api')
    @patch('kubernetes.config.load_kube_config')
    def test_null(self, mock_config, mock_client):
        mock_config.return_value = None
        mock_client.return_value = MockClient(
            client.V1IngressList(
                items=[
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(name='no_annotation'),
                        status=client.V1IngressStatus(),
                    ),
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='no_status',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'no_status.example.com'
                            },
                        )
                    ),
                ]
            )
        )
        zone = Zone('example.com.', [])
        KubernetesSource('dynamic').populate(zone)
        self.assertEqual(0, len(zone.records))

    @patch('kubernetes.client.NetworkingV1Api')
    @patch('kubernetes.config.load_kube_config')
    def test_invalid(self, mock_config, mock_client):
        mock_config.return_value = None
        mock_client.return_value = MockClient(
            client.V1IngressList(
                items=[
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='not_configured',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'not_configured.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(ip='1.1.1.1')
                                ]
                            )
                        ),
                    ),
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='invalid_ip',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'invalid_ip.example.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        ip='256.256.256.256'
                                    )
                                ]
                            )
                        ),
                    ),
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='invalid_hostname',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'invalid_hostname.example.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        hostname='invalid_hostname'
                                    )
                                ]
                            )
                        ),
                    ),
                ]
            )
        )
        zone = Zone('example.com.', [])

        with self.assertRaises(ValidationError):
            KubernetesSource('dynamic').populate(zone, lenient=False)

        KubernetesSource('dynamic').populate(zone, lenient=True)
        self.assertEqual(1, len(zone.records))

    @patch('kubernetes.client.NetworkingV1Api')
    @patch('kubernetes.config.load_kube_config')
    def test_duplicates(self, mock_config, mock_client):
        mock_config.return_value = None
        mock_client.return_value = MockClient(
            client.V1IngressList(
                items=[
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='duplicate_hostnames',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'duplicate_hostname.example.com,duplicate_hostname.example.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        ip='1:1:1:1:1:1:1:1'
                                    )
                                ]
                            )
                        ),
                    )
                ]
            )
        )
        zone = Zone('example.com.', [])
        KubernetesSource('dynamic').populate(zone)
        self.assertEqual(1, len(zone.records))
        self.assertEqual(type(sorted(zone.records)[0]), AaaaRecord)
        self.assertEqual(sorted(zone.records)[0].values, ['1:1:1:1:1:1:1:1'])

    @patch('kubernetes.client.NetworkingV1Api')
    @patch('kubernetes.config.load_kube_config')
    def test_target(self, mock_config, mock_client):
        mock_config.return_value = None
        mock_client.return_value = MockClient(client.V1IngressList(items=[]))
        zone = Zone('example.com.', [])
        with self.assertRaises(NotImplementedError):
            KubernetesSource('dynamic').populate(zone, target=True)
        self.assertEqual(0, len(zone.records))

    @patch('kubernetes.client.NetworkingV1Api')
    @patch('kubernetes.config.load_kube_config')
    def test_cname_and_ip(self, mock_config, mock_client):
        mock_config.return_value = None
        mock_client.return_value = MockClient(
            client.V1IngressList(
                items=[
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='cname_and_ip',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'cname_and_ip.example.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        ip='1:1:1:1:1:1:1:1'
                                    ),
                                    client.V1LoadBalancerIngress(
                                        hostname='cname.example.com'
                                    ),
                                ]
                            )
                        ),
                    )
                ]
            )
        )
        zone = Zone('example.com.', [])
        KubernetesSource('dynamic').populate(zone)
        self.assertEqual(1, len(zone.records))
        self.assertEqual(type(sorted(zone.records)[0]), AaaaRecord)
        self.assertEqual(sorted(zone.records)[0].values, ['1:1:1:1:1:1:1:1'])

    @patch('kubernetes.client.NetworkingV1Api')
    @patch('kubernetes.config.load_kube_config')
    def test_lenient(self, mock_config, mock_client):
        mock_config.return_value = None
        mock_client.return_value = MockClient(
            client.V1IngressList(
                items=[
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='lenient_duplicate_one',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'duplicate.example.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        ip='1:1:1:1:1:1:1:1'
                                    )
                                ]
                            )
                        ),
                    ),
                    client.V1Ingress(
                        metadata=client.V1ObjectMeta(
                            name='lenient_duplicate_two',
                            annotations={
                                KubernetesSource.DEFAULT_HOSTNAME_ANNOTATIONS[
                                    0
                                ]: 'duplicate.example.com'
                            },
                        ),
                        status=client.V1IngressStatus(
                            load_balancer=client.V1LoadBalancerStatus(
                                ingress=[
                                    client.V1LoadBalancerIngress(
                                        ip='2:2:2:2:2:2:2:2'
                                    )
                                ]
                            )
                        ),
                    ),
                ]
            )
        )
        zone = Zone('example.com.', [])
        with self.assertRaises(DuplicateRecordException):
            KubernetesSource('dynamic').populate(zone, lenient=False)
        self.assertEqual(1, len(zone.records))
        self.assertEqual(type(sorted(zone.records)[0]), AaaaRecord)
        self.assertEqual(sorted(zone.records)[0].values, ['1:1:1:1:1:1:1:1'])
        zone = Zone('example.com.', [])
        KubernetesSource('dynamic').populate(zone, lenient=True)
        self.assertEqual(1, len(zone.records))
        self.assertEqual(type(sorted(zone.records)[0]), AaaaRecord)
        self.assertEqual(sorted(zone.records)[0].values, ['1:1:1:1:1:1:1:1'])
