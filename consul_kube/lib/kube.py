import json
import time
from datetime import datetime
from io import StringIO
from typing import Tuple, List, Dict, Optional

from OpenSSL import crypto
from jsonpath_ng.ext import parse
from kubernetes import client, config
from kubernetes.client.models import V1Node, V1Pod, ExtensionsV1beta1Deployment, ExtensionsV1beta1DeploymentSpec, \
    V1DeleteOptions, V1Container, V1ObjectMeta, V1PodSpec, V1PodTemplateSpec
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from kubernetes.stream.ws_client import WSClient
from urllib3.response import HTTPResponse

from consul_kube.lib import JSONNode
from consul_kube.lib.color import debug, error, color_assert
from consul_kube.lib.tar import TarInMemory
from consul_kube.lib.x509 import load_certs, cert_from_pem, cert_to_pem, pkey_from_pem, pkey_to_pem, \
    extract_cert, cert_digest

config.load_kube_config()
kube = client.CoreV1Api()
kube_beta = client.ExtensionsV1beta1Api()


def init_kube_api(context_name: str = None) -> None:
    config.load_kube_config(context=context_name)


class ConsulApiClient:
    CONSUL_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

    def __init__(self, pod_name: str = None, service_name: str = 'consul-server:8500',
                 namespace: str = 'default') -> None:
        self._namespace = namespace
        if pod_name:
            self._name = pod_name
            self._path = '/api/v1/namespaces/{namespace}/pods/{name}/proxy/{path}'
            self._http_func = kube.connect_get_namespaced_pod_proxy_with_path_with_http_info
        else:
            self._name = service_name
            self._path = '/api/v1/namespaces/{namespace}/services/{name}/proxy/{path}'
            self._http_func = kube.connect_get_namespaced_service_proxy_with_path_with_http_info

    def get(self, path: str) -> JSONNode:
        response = self._http_func(self._name, self._namespace, path,
                                   _preload_content=False, _return_http_data_only=True)  # type: HTTPResponse
        assert response.status < 400, f"Invalid response from Consul server: HTTP error {response.status}"
        return json.loads(response.data)

    def put(self, path: str, payload: JSONNode) -> None:
        path_params = {'name': self._name, 'namespace': self._namespace, 'path': path}
        header_params = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        return kube.api_client.call_api(self._path, 'PUT',
                                        path_params=path_params,
                                        query_params=[],
                                        header_params=header_params,
                                        post_params=[],
                                        files={},
                                        collection_formats={},
                                        body=payload,
                                        response_type='str',
                                        auth_settings=['BearerToken'],
                                        async_req=False,
                                        _preload_content=True,
                                        _return_http_data_only=False,
                                        _request_timeout=None
                                        )

    @property
    def active_ca_root_cert(self) -> Tuple[crypto.X509, dict]:
        response_json = self.get('/v1/connect/ca/roots')  # type: dict
        active_root_id = response_json['ActiveRootID']
        for root in response_json['Roots']:
            if root['ID'] != active_root_id:
                continue
            assert root['Active'], "Certificate is inactive but is set as ActiveRootID"
            return cert_from_pem(root['RootCert']), response_json

        raise RuntimeError('Cannot find an active root certificate in the CA')

    def leaf_cert(self, service_name: str) -> Tuple[List[crypto.X509], crypto.PKey, dict]:
        response_json = self.get(f'/v1/agent/connect/ca/leaf/{service_name}')
        return (load_certs(StringIO(response_json['CertPEM'])),
                pkey_from_pem(response_json['PrivateKeyPEM']),
                response_json)

    def update_config(self, private_key: crypto.PKey, root_ca_cert: crypto.X509,
                      leaf_cert_ttl: str = '72h', rotation_period: str = '2160h'):
        payload = {
            "Provider": "consul",
            "Config": {
                "PrivateKey": pkey_to_pem(private_key).decode('utf-8'),
                "RootCert": cert_to_pem(root_ca_cert).decode('utf-8'),
                "LeafCertTTL": leaf_cert_ttl,
                "RotationPeriod": rotation_period
            }
        }
        return self.put('/v1/connect/ca/configuration', payload)

    @staticmethod
    def convert_api_date(api_date_str: str) -> datetime:
        return datetime.strptime(api_date_str, ConsulApiClient.CONSUL_DATETIME_FORMAT)


# noinspection PyUnresolvedReferences
class KubeThing:
    DEFAULT_NAMESPACE = 'default'

    def __init__(self, thing: object) -> None:
        super().__init__()
        self._thing = thing

    @property
    def name(self) -> str:
        return self._thing.metadata.name

    @property
    def namespace(self) -> str:
        return self._thing.metadata.namespace

    @property
    def annotations(self) -> Dict[str, str]:
        return self._thing.metadata.annotations or dict()

    def to_json(self):
        return self._thing.to_dict()


# noinspection PyUnresolvedReferences
class KubeNode(KubeThing):

    def __init__(self, node: V1Node) -> None:
        super().__init__(node)
        self._node = node

    @staticmethod
    def list_all() -> List['KubeNode']:
        return [KubeNode(x) for x in kube.list_node().items]

    @staticmethod
    # TODO: this should work, but there seems to be a bug in jsonpath_ng
    # return [KubeNode(x) for x in kube.list_node().items if parsed.find(x.to_dict())]
    def find(pattern: str) -> List['KubeNode']:
        parsed = parse(pattern)
        all_nodes = kube.list_node()
        results = []
        for match in parsed.find(all_nodes.to_dict()):
            node_name = match.value['metadata']['name']
            for node in all_nodes.items:
                if node.metadata.name == node_name:
                    results.append(node)

        return results

    @staticmethod
    def find_one(pattern: str) -> 'KubeNode':
        results = KubeNode.find(pattern)
        assert len(results) == 1
        return results[0]


# noinspection PyUnresolvedReferences
class KubePod(KubeThing):
    ANNOTATION_INJECT = 'consul.hashicorp.com/connect-inject'
    ANNOTATION_INJECT_STATUS = 'consul.hashicorp.com/connect-inject-status'
    ANNOTATION_SERVICE_NAME = 'consul.hashicorp.com/connect-service'
    ANNOTATION_UPSTREAMS = 'consul.hashicorp.com/connect-service-upstreams'
    INJECT_BY_DEFAULT = 'false'

    def __init__(self, pod: V1Pod) -> None:
        super().__init__(pod)

    @property
    def wants_inject(self) -> bool:
        return self.annotations.get(KubePod.ANNOTATION_INJECT, KubePod.INJECT_BY_DEFAULT).lower() == 'true'

    @property
    def is_injected(self) -> bool:
        return self.annotations.get(KubePod.ANNOTATION_INJECT_STATUS, '').lower() == 'injected'

    @property
    def service_name(self) -> str:
        return self.annotations.get(KubePod.ANNOTATION_SERVICE_NAME, None)

    @property
    def host_ip(self) -> str:
        return self._thing.status.host_ip

    @property
    def pod_ip(self) -> str:
        return self._thing.status.pod_ip

    @property
    def upstreams(self) -> List[Tuple[str, int]]:
        ups = []
        for upstream_def in self.annotations.get(KubePod.ANNOTATION_UPSTREAMS, '').split(','):
            upstream_def = upstream_def.strip()
            if ':' in upstream_def:
                service_name, port_number = upstream_def.split(':')
                ups.append((service_name, int(port_number)))

        return ups

    @property
    def envoy_config(self, container_name: str = 'consul-connect-envoy-sidecar',
                     envoy_port: int = 19000) -> Optional[JSONNode]:
        try:
            ws_client: WSClient = stream(kube.connect_get_namespaced_pod_exec_with_http_info,
                                         self.name, self.namespace, container=container_name,
                                         tty=False, stdout=True, stderr=True,
                                         command=['wget', '-q', '-O', '-', f'localhost:{envoy_port}/config_dump'],
                                         _preload_content=False, _return_http_data_only=True)
            ws_client.run_forever()
            config_txt = ws_client.read_all()
            return json.loads(config_txt)
        except ApiException:
            return None

    def send_files(self, files: TarInMemory, dest_dir: str = '/tmp', container_name: str = None):
        ws_client: WSClient = stream(kube.connect_get_namespaced_pod_exec,
                                     self.name, self.namespace, container=container_name,
                                     tty=False, stdin=True, stdout=True, stderr=True, _preload_content=False,
                                     command=['/bin/tar', 'xf', '-', '-C', dest_dir])
        ws_client.write_stdin(files.close().decode('utf-8'))
        ws_client.update()
        if ws_client.peek_stderr():
            raise RuntimeError(ws_client.read_stderr())
        ws_client.close()

    @staticmethod
    def list_all() -> List['KubePod']:
        return [KubePod(x) for x in kube.list_pod_for_all_namespaces()]

    @staticmethod
    def list_namespace(namespace: str = KubeThing.DEFAULT_NAMESPACE) -> List['KubePod']:
        return [KubePod(x) for x in kube.list_namespaced_pod(namespace)]

    @staticmethod
    def select(selector: str, namespace: str = KubeThing.DEFAULT_NAMESPACE, **kwargs) -> List['KubePod']:
        return [KubePod(x) for x in kube.list_namespaced_pod(namespace, label_selector=selector, **kwargs).items]

    @staticmethod
    def select_one(selector: str, namespace: str = KubeThing.DEFAULT_NAMESPACE, **kwargs) -> 'KubePod':
        results = KubePod.select(selector, namespace, **kwargs)
        assert len(results) == 1
        return results[0]

    @staticmethod
    def injected(inject_by_default: str = 'true') -> List['KubePod']:
        KubePod.INJECT_BY_DEFAULT = inject_by_default
        all_pods = [KubePod(x) for x in kube.list_pod_for_all_namespaces().items]
        return [x for x in all_pods if x.wants_inject]


class SSLProxyContainer:

    def __init__(self, name: str = "openssl", namespace: str = "default",
                 image: str = "securefab/openssl:latest") -> None:
        super().__init__()
        self._name = name
        self._namespace = namespace
        self._image = image
        self.deploy()
        self.wait_for_ready()

    @property
    def name(self):
        return self._name

    @property
    def namespace(self):
        return self._namespace

    @property
    def image(self):
        return self._image

    def deploy(self) -> ExtensionsV1beta1Deployment:
        if self.exists:
            return self.update()
        else:
            return self.create()

    def create(self) -> ExtensionsV1beta1Deployment:
        debug('Creating OpenSSL proxy deployment')
        try:
            return kube_beta.create_namespaced_deployment(namespace=self._namespace,
                                                          body=self._build())
        except ApiException as ex:
            body = json.loads(ex.body)
            error(f'Unable to create OpenSSL proxy: {body["message"]}')
            raise

    def update(self) -> ExtensionsV1beta1Deployment:
        debug('Updating OpenSSL proxy deployment')
        try:
            return kube_beta.patch_namespaced_deployment(name=self._name,
                                                         namespace=self._namespace,
                                                         body=self._build())
        except ApiException as ex:
            body = json.loads(ex.body)
            error(f'Error updating OpenSSL proxy: {body["message"]}')
            raise

    def delete(self) -> None:
        debug('Deleting OpenSSL proxy deployment')
        delete_opts = V1DeleteOptions(api_version="extensions/v1beta1",
                                      grace_period_seconds=0)
        try:
            return kube_beta.delete_namespaced_deployment(name=self._name,
                                                          namespace=self._namespace,
                                                          body=delete_opts)
        except ApiException:
            pass

    def _build(self) -> ExtensionsV1beta1Deployment:
        container = V1Container(name="openssl",
                                image=self._image,
                                command=["/bin/sh", "-c", "--"],
                                args=["while true; do sleep 30; done;"])
        template = V1PodTemplateSpec(metadata=V1ObjectMeta(labels={"app": self._name}),
                                     spec=V1PodSpec(containers=[container]))
        spec = ExtensionsV1beta1DeploymentSpec(replicas=1, template=template)
        return ExtensionsV1beta1Deployment(api_version="extensions/v1beta1",
                                           kind="Deployment",
                                           metadata=V1ObjectMeta(name=self._name),
                                           spec=spec)

    def get(self) -> ExtensionsV1beta1Deployment:
        return kube_beta.read_namespaced_deployment(name=self._name, namespace=self._namespace)

    @property
    def exists(self) -> bool:
        try:
            self.get()
            return True
        except ApiException as ex:
            if ex.status == 404:
                return False
            raise

    def is_ready(self) -> bool:
        my_deploy = self.get()
        debug(f'Available replicas = {my_deploy.status.available_replicas}')
        return my_deploy.status.available_replicas is not None and my_deploy.status.available_replicas >= 1

    def wait_for_ready(self) -> None:
        debug('Waiting for OpenSSL proxy container to become ready')
        while not self.is_ready():
            debug('Sleeping for 10 seconds')
            time.sleep(10)

    @property
    def pod(self) -> KubePod:
        return KubePod.select_one('app=openssl', field_selector='status.phase==Running')

    def connect(self, host: str, port: int) -> Optional[crypto.X509]:
        debug(f'Using OpenSSL proxy container to connect to {host}:{port}')
        command = ['openssl', 's_client',
                   '-prexit',
                   '-no_tls1_2',
                   '-cipher', 'ECDHE-ECDSA-AES128-SHA',
                   '-cert', '/tmp/client.pem',
                   '-key', '/tmp/client.key',
                   '-CAfile', '/tmp/root_ca.pem',
                   '-connect', f'{host}:{port}']
        debug(f'Executing: ' + ' '.join(command))
        command_out = stream(kube.connect_get_namespaced_pod_exec,
                             self.pod.name, self.pod.namespace, container='openssl',
                             tty=False, stdout=True, stderr=True,
                             command=command)

        debug(f'Output from OpenSSL command: \n{command_out}')

        if 'command terminated with exit code 1' in command_out or ':error:' in command_out:
            error(f'OpenSSL command failed with output:\n{command_out}')
            return None

        certs = extract_cert(command_out)
        color_assert(len(certs) > 0, 'Did not receive a certificate in the server response')
        return certs[0]

    def update_certs(self, root_ca_cert: crypto.X509 = None,
                     client_cert: crypto.X509 = None,
                     client_key: crypto.PKey = None) -> None:
        debug('Updating certificates in OpenSSL proxy container')
        tar = TarInMemory()
        if root_ca_cert:
            debug('Updating root CA certificate with fingerprint ' + cert_digest(root_ca_cert))
            tar.add("root_ca.pem", cert_to_pem(root_ca_cert))
        if client_cert:
            debug('Updating client certificate with fingerprint ' + cert_digest(client_cert))
            tar.add("client.pem", cert_to_pem(client_cert))
        if client_key:
            debug('Updating private key')
            tar.add("client.key", pkey_to_pem(client_key))

        debug('Sending updated certificates to container')
        self.pod.send_files(tar, container_name='openssl')
