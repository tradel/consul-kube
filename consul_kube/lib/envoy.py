from typing import Dict, List, Optional
from datetime import datetime
from io import StringIO

from OpenSSL import crypto

from jsonpath_ng.ext import parse
from jsonpath_ng.jsonpath import DatumInContext

from consul_kube.lib import JSONNode
from consul_kube.lib.x509 import load_certs, pkey_from_pem


class EnvoyBaseConfig:
    ENVOY_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

    def __init__(self, json_obj: dict) -> None:
        self._config = json_obj

    def _find(self, pattern: str, root_obj: JSONNode = None) -> List[DatumInContext]:
        parser = parse(pattern)
        return parser.find(root_obj or self._config)

    def _find_one(self, pattern: str, root_obj: JSONNode = None) -> JSONNode:
        results = self._find(pattern, root_obj)
        if len(results) == 0:
            raise RuntimeError(f'JSONPath pattern not found: {pattern}')
        elif len(results) > 1:
            raise RuntimeError(f'Found multiple matches when expecting only one: {pattern}')
        else:
            return results[0].value

    # noinspection PyMethodMayBeStatic
    def _convert_date(self, dt: str) -> datetime:
        return datetime.strptime(dt.replace('Z', '000Z'), self.ENVOY_DATETIME_FORMAT)


class EnvoyClusterConfig(EnvoyBaseConfig):

    def __init__(self, json_obj: dict) -> None:
        super().__init__(json_obj)

    @property
    def name(self) -> str:
        return self._find_one("$.cluster.name", self._config)

    @property
    def type(self) -> str:
        return self._find_one("$._type", self._config)

    @property
    def target(self) -> str:
        return self._find_one("$._target", self._config)

    @property
    def target_address(self) -> str:
        assert self.type != 'service'
        assert len(self._find("$.cluster.hosts")) == 1
        return self._find_one("$.cluster.hosts[0].socket_address.address", self._config)

    @property
    def target_port(self) -> int:
        assert self.type != 'service'
        assert len(self._find("$.cluster.hosts")) == 1
        return self._find_one("$.cluster.hosts[0].socket_address.port_value", self._config)

    @property
    def private_key_pem(self) -> Optional[str]:
        return self._find_one("$.cluster.tls_context.common_tls_context"
                              ".tls_certificates[*].private_key.inline_string",
                              self._config) if self.type == 'service' else None

    @property
    def private_key(self):
        return pkey_from_pem(self.private_key_pem.encode('utf-8'))

    @property
    def client_cert_pem(self) -> Optional[str]:
        return self._find_one("$.cluster.tls_context.common_tls_context"
                              ".tls_certificates[*].certificate_chain.inline_string",
                              self._config) if self.type == 'service' else None

    @property
    def client_certs(self) -> Optional[List[crypto.X509]]:
        return load_certs(StringIO(self.client_cert_pem)) if self.type == 'service' else None

    @property
    def root_ca_pem(self) -> Optional[str]:
        return self._find_one("$.cluster.tls_context.common_tls_context"
                              ".validation_context.trusted_ca.inline_string",
                              self._config) if self.type == 'service' else None

    @property
    def root_certs(self) -> Optional[List[crypto.X509]]:
        return load_certs(StringIO(self.root_ca_pem)) if self.type == 'service' else None

    @property
    def last_update(self):
        return self._convert_date(self._config['last_updated'])

    @property
    def age(self):
        return datetime.utcnow() - self.last_update


class EnvoyListenerConfig(EnvoyBaseConfig):

    def __init__(self, json_obj: dict) -> None:
        super().__init__(json_obj)

    @property
    def name(self) -> str:
        return self._find_one("$.listener.name", self._config)

    @property
    def target(self) -> str:
        return self._find_one("$._target", self._config)

    @property
    def bind_address(self) -> str:
        return self._find_one("$.listener.address.socket_address.address", self._config)

    @property
    def bind_port(self) -> int:
        return self._find_one("$.listener.address.socket_address.port_value", self._config)

    @property
    def private_key_pem(self) -> str:
        return self._find_one("$.listener.filter_chains[0].tls_context.common_tls_context"
                              ".tls_certificates[*].private_key.inline_string",
                              self._config)

    @property
    def private_key(self):
        return pkey_from_pem(self.private_key_pem.encode('utf-8'))

    @property
    def root_ca_pem(self) -> str:
        return self._find_one("$.listener.filter_chains[0].tls_context.common_tls_context"
                              ".validation_context.trusted_ca.inline_string",
                              self._config)

    @property
    def ca_certificates(self) -> List[crypto.X509]:
        return load_certs(StringIO(self.root_ca_pem))

    @property
    def certificate_pem(self) -> str:
        return self._find_one("$.listener.filter_chains[0].tls_context.common_tls_context"
                              ".tls_certificates[*].certificate_chain.inline_string",
                              self._config)

    @property
    def certificates(self) -> List[crypto.X509]:
        return load_certs(StringIO(self.certificate_pem))

    @property
    def last_update(self):
        return self._convert_date(self._config['last_updated'])

    @property
    def age(self):
        return datetime.utcnow() - self.last_update


class EnvoyConfig(EnvoyBaseConfig):
    GRPC_BOOTSTRAP_TYPE = 'type.googleapis.com/envoy.admin.v2alpha.BootstrapConfigDump'
    GRPC_LISTENERS_TYPE = 'type.googleapis.com/envoy.admin.v2alpha.ListenersConfigDump'
    GRPC_CLUSTERS_TYPE = 'type.googleapis.com/envoy.admin.v2alpha.ClustersConfigDump'

    def __init__(self, json_obj: dict) -> None:
        super().__init__(json_obj)
        self._clusters = None
        self._listeners = None

    @property
    def bootstrap(self) -> dict:
        return self._find_one(f"$.configs[?(@.'@type' == '{self.GRPC_BOOTSTRAP_TYPE}')]")

    @property
    def clusters(self) -> dict:
        if not self._clusters:
            self._clusters = self._find_one(f"$.configs[?(@.'@type' == '{self.GRPC_CLUSTERS_TYPE}')]")
            for dyn in self._clusters['static_clusters']:  # type: dict
                dyn.update(self._parse_cluster_name(dyn['cluster']['name']))
            for dyn in self._clusters['dynamic_active_clusters']:  # type: dict
                dyn.update(self._parse_cluster_name(dyn['cluster']['name']))

        return self._clusters

    # noinspection PyMethodMayBeStatic
    def _parse_cluster_name(self, name: str) -> Dict[str, str]:
        tokens = name.split(':')
        return {'_type': tokens.pop(0), '_target': ':'.join(tokens)}

    @property
    def listeners(self) -> dict:
        if not self._listeners:
            self._listeners = self._find_one(f"$.configs[?(@.'@type' == '{self.GRPC_LISTENERS_TYPE}')]")
            for dyn in self._listeners['dynamic_active_listeners']:  # type: dict
                dyn.update(self._parse_listener_name(dyn['listener']['name']))

        return self._listeners

    # noinspection PyMethodMayBeStatic
    def _parse_listener_name(self, name: str) -> Dict[str, str]:
        tokens = name.split(':')
        return {'_port': int(tokens.pop()), '_ip': tokens.pop(), '_type': tokens.pop(0), '_target': ':'.join(tokens)}

    @property
    def node_id(self) -> str:
        return self._find("$.bootstrap.node.id", self.bootstrap)[0].value

    @property
    def agent_ip(self) -> str:
        return self._find_one("$.bootstrap.static_resources"
                              ".clusters[?(@.name == 'local_agent')]"
                              ".hosts[0].socket_address.address",
                              self.bootstrap)

    @property
    def admin_port(self) -> int:
        return self._find_one("$.bootstrap.admin.address.socket_address.port_value",
                              self.bootstrap)

    def downstream(self, name: str) -> EnvoyListenerConfig:
        return EnvoyListenerConfig(self._find_one(f"$.dynamic_active_listeners[?(@._target == '{name}')]",
                                                  self.listeners))

    def listener(self, name: str) -> EnvoyListenerConfig:
        return EnvoyListenerConfig(self._find_one(f"$.dynamic_active_listeners[?(@.name == '{name}')]",
                                                  self.listeners))

    @property
    def public_listener(self) -> EnvoyListenerConfig:
        return EnvoyListenerConfig(self._find_one("$.dynamic_active_listeners[?(@.'_type' == 'public_listener')]",
                                                  self.listeners))

    def upstream(self, name: str) -> EnvoyClusterConfig:
        return EnvoyClusterConfig(self._find_one(f"$.dynamic_active_clusters[?(@._target == '{name}')]",
                                                 self.clusters))

    def cluster(self, name: str) -> EnvoyClusterConfig:
        return EnvoyClusterConfig(self._find_one(f"$.dynamic_active_clusters[?(@.cluster.name == '{name}')]",
                                                 self.clusters))

    @property
    def local_app(self):
        return self.cluster('local_app')

    @property
    def local_agent(self):
        return EnvoyClusterConfig(self._find_one("$.static_clusters[?(@.cluster.name == 'local_agent')]",
                                                 self.clusters))
