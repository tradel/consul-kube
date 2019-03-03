import re
from datetime import datetime
from typing import Tuple, List, Optional

import click
from OpenSSL import crypto
from jsonpath_ng.ext import parse

from consul_kube.lib.color import debug, info, error, color_assert, section, groovy
from consul_kube.lib.envoy import EnvoyListenerConfig, EnvoyClusterConfig, EnvoyConfig
from consul_kube.lib.kube import ConsulApiClient, KubePod, SSLProxyContainer
from consul_kube.lib.x509 import validate_cert, save_cert, save_key, cert_digest, get_subject_alt_name, \
    get_subject_cn, cert_in_list, get_valid_times, compare_certs


def validate_spiffe(cert: crypto.X509, domain: str) -> bool:
    debug('Validating SPIFFE trust domain')
    alt_name = get_subject_alt_name(cert)
    debug(f'Subject alt name of cert is {alt_name}')
    return color_assert(alt_name is not None,
                        'CA root cert does not contain a subjectAltName') and \
           color_assert(alt_name[0:2] == b"06",
                        f"SubjectAltName of root certificate is not a URI: {alt_name}") and \
           color_assert(alt_name[4:].decode('utf-8') == f'spiffe://{domain}',
                        f"SAN of root certificate does not match Consul trust domain: {alt_name}",
                        'SPIFFE URL in root certificate matches CA trust domain')


def validate_ca_root(cert: crypto.X509) -> bool:
    section('Validating CA root certificate')
    msg = validate_cert(cert, cert)
    return color_assert(msg is None, f'CA root validation failed: {msg}', 'CA root validation succeeded')


def get_ca_root(namespace: str) -> Tuple[crypto.X509, str]:
    debug('Getting CA root certificate from Consul server')
    api_client = ConsulApiClient(namespace=namespace)
    ca_root_cert, api_result = api_client.active_ca_root_cert
    save_cert("ca_root.pem", [ca_root_cert])
    return ca_root_cert, api_result['TrustDomain']


def get_injector_default(namespace: str) -> str:
    debug('Finding the Connect injector pod')

    injector_pod = KubePod.select_one('app=consul,component=connect-injector', namespace=namespace)

    pattern = parse("$.spec.containers[?(@.name == 'sidecar-injector')].command")
    match = pattern.find(injector_pod.to_json())
    assert len(match) == 1

    command = ' '.join(match[0].value)

    default = 'true'
    regex = re.compile(r'-default-inject=(\w+)')
    matches = regex.search(command)
    if matches:
        default = matches.group(1)

    debug(f'Default injection flag if not specified for a pod: {default}')
    return default


def print_fingerprints(name: str, certs: List[crypto.X509]) -> None:
    if len(certs) == 0:  # pylint: disable=C1801
        debug(f'{name} has no certificates')
    elif len(certs) == 1:
        debug(f'{name} has fingerprint {cert_digest(certs[0])}')
    else:
        debug(f'{name} has multiple certificates:')
        for cert in certs:
            debug(f'    {cert_digest(cert)}')


def find_matching_cert(key: crypto.PKey, *args: crypto.X509) -> Optional[crypto.X509]:
    for cert in args:
        data = 'Jeremiah was a bullfrog'
        signed = crypto.sign(key, data, 'sha256')
        if not crypto.verify(cert, signed, data, 'sha256'):
            debug(f'Certificate matching private key has fingerprint: {cert_digest(cert)}')
            return cert
    else:
        return None


def validate_envoy_public_listener(pub: EnvoyListenerConfig, ca_root: crypto.X509) -> None:
    print_fingerprints('Envoy public listener', pub.certificates)
    active_cert = find_matching_cert(pub.private_key, *pub.certificates)
    pub_msg = validate_cert(active_cert, *pub.ca_certificates)
    color_assert(pub_msg is None,
                 f'Validation of Envoy public listener cert failed: {pub_msg}',
                 'Envoy public listener cert is valid')
    color_assert(cert_in_list(ca_root, *pub.ca_certificates),
                 'Envoy listener cert has different root from CA root')


def find_agent_pod_by_ip(ip_address: str, namespace: str) -> Optional[KubePod]:
    for agent_pod in KubePod.select('app=consul,component=client', namespace=namespace):
        if agent_pod.host_ip == ip_address:
            debug(f'Agent pod identified as {agent_pod.name}')
            return agent_pod
    else:
        error(f"Could not find an agent pod to match the IP address supplied by Envoy ({ip_address})")
        return None


def get_envoy_config(pod: KubePod) -> Optional[EnvoyConfig]:
    debug('Getting Envoy proxy config from pod')
    if pod.envoy_config:
        return EnvoyConfig(pod.envoy_config)
    else:
        error(f'Could not get Envoy proxy config for pod {pod.name}')
        return None


def validate_pod_injected(pod: KubePod) -> bool:
    return color_assert(pod.is_injected, 'Pod is not injected', 'Pod was successfully injected')


def validate_leaf_cn(pod: KubePod, cert: crypto.X509) -> bool:
    leaf_cn = get_subject_cn(cert)
    debug(f'Subject CN: {leaf_cn}')
    return color_assert(leaf_cn == pod.service_name,
                        f"Certificate subject name does not match service name: {leaf_cn}",
                        f"Certificate subject name of {leaf_cn} matches service name")


def get_leaf_cert(agent_ip: str, service_name: str, namespace: str) -> Optional[Tuple[crypto.X509, crypto.PKey, dict]]:
    agent_pod = find_agent_pod_by_ip(agent_ip, namespace=namespace)
    if not agent_pod:
        return None
    agent_cc = ConsulApiClient(pod_name=f"{agent_pod.name}:8500")
    leaf_certs, leaf_key, leaf_json = agent_cc.leaf_cert(service_name)
    print_fingerprints('Agent leaf cert', leaf_certs)
    active_cert = find_matching_cert(leaf_key, *leaf_certs)
    return active_cert, leaf_key, leaf_json


def validate_leaf_dates(cert: crypto.X509, api_result: dict) -> bool:
    before, after = get_valid_times(cert)
    now = datetime.utcnow()
    return color_assert(before <= now, "Certificate is not yet valid") and \
           color_assert(now <= after, "Certificate has expired", "Certificate has not expired") and \
           color_assert(before == ConsulApiClient.convert_api_date(api_result['ValidAfter']),
                        "Certificate start date does not match API results") and \
           color_assert(after == ConsulApiClient.convert_api_date(api_result['ValidBefore']),
                        "Certificate end date does not match API results")


def validate_leaf_chain(cert: crypto.X509, ca_root: crypto.X509) -> bool:
    debug('Validating leaf certificate')
    msg = validate_cert(cert, ca_root)
    return color_assert(msg is None, f'Leaf cert validation failed: {msg}', 'Leaf cert validation succeeded')


def validate_listener_chain(certs: List[crypto.X509], private_key: crypto.PKey, ca_roots: List[crypto.X509],
                            leaf_cert: crypto.X509, ca_root: crypto.X509) -> bool:
    debug('Validating Envoy public listener certificate')
    print_fingerprints('Envoy public listener certificate', certs)
    active_cert = find_matching_cert(private_key, *certs)
    msg = validate_cert(active_cert, *ca_roots)
    return color_assert(msg is None, f'Unable to validate listener cert: {msg}') and \
           color_assert(compare_certs(active_cert, leaf_cert),
                        'Listener cert is not the same as Consul leaf cert',
                        'Listener cert matches Consul leaf cert') and \
           color_assert(cert_in_list(ca_root, *ca_roots),
                        'Envoy listener cert has different root from CA root')


def validate_conn_chain(conn_cert: crypto.X509, leaf_cert: crypto.X509, ca_root: crypto.X509, address: str) -> bool:
    debug(f'Validating certificate returned from {address}')
    msg = validate_cert(conn_cert, ca_root)
    return color_assert(msg is None, f'Unable to validate cert from {address}: {msg}',
                        f'Certificate served by Envoy from {address} is valid') and \
           color_assert(compare_certs(conn_cert, leaf_cert),
                        f'Certificate served from {address} is not the same as Consul leaf cert',
                        f'Certificate served from {address} matches Consul leaf cert')


def validate_conn(host: str, port: int, leaf_cert: crypto.X509, leaf_key: crypto.PKey, ca_root: crypto.X509,
                  openssl: SSLProxyContainer) -> bool:
    openssl.update_certs(root_ca_cert=ca_root, client_cert=leaf_cert, client_key=leaf_key)

    conn_cert = openssl.connect(host, port)
    if not conn_cert:
        return False

    debug(f'Certificate served by Envoy has fingerprint {cert_digest(conn_cert)}')
    return validate_conn_chain(conn_cert, leaf_cert, ca_root, f'{host}:{port}')


def validate_upstream_chain(upstream: EnvoyClusterConfig,
                            leaf_cert: crypto.X509, root_ca: crypto.X509) -> bool:
    debug(f'Validating upstream connection to {upstream.name}')
    print_fingerprints('Upstream client certificate', upstream.client_certs)
    active_cert = find_matching_cert(upstream.private_key, *upstream.client_certs)
    msg = validate_cert(active_cert, *upstream.root_certs)
    return color_assert(msg is None,
                        f'Unable to validate cert for upstream {upstream.name}: {msg}',
                        f'Certificate configured for upstream {upstream.name} is valid') and \
           color_assert(cert_in_list(root_ca, *upstream.root_certs),
                        'None of the configured root CA certs match') and \
           color_assert(compare_certs(active_cert, leaf_cert),
                        f"Envoy client cert for {upstream.name} does not match leaf cert")


def validate_downstream_config(downstream: EnvoyListenerConfig, upstream_name: str, upstream_port: int) -> bool:
    debug(f'Validating downstream configuration for {downstream.name}')
    return color_assert(downstream.target == upstream_name,
                        "Downstream target service in Envoy listener config name does not match pod annotation") and \
           color_assert(downstream.bind_port == int(upstream_port),
                        "Downstream port number in Envoy listener config does not match pod annotation")


def validate_command(ctx: click.Context) -> None:
    namespace = ctx.obj['namespace']
    clean_openssl = ctx.obj['clean_openssl']
    debug(f'Will use namespace "{namespace}" in Kubernetes')

    openssl = SSLProxyContainer(namespace=namespace)

    root_cert, trust_domain = get_ca_root(namespace)
    validate_ca_root(root_cert)
    validate_spiffe(root_cert, trust_domain)
    info(f'Consul CA root certificate serial number is {root_cert.get_serial_number()}')

    default_inject = get_injector_default(namespace)

    debug('Getting list of Kubernetes pods with Connect injection configured')
    for pod in KubePod.injected(default_inject):
        section(f'Validating pod: {pod.name}')

        service_name = pod.service_name
        debug(f'Pod service name is {service_name}')

        if not validate_pod_injected(pod):
            continue

        envoy_config = get_envoy_config(pod)
        if not envoy_config:
            continue

        validate_envoy_public_listener(envoy_config.public_listener, root_cert)

        leaf_cert, leaf_key, leaf_json = get_leaf_cert(envoy_config.agent_ip, service_name, namespace)
        validate_leaf_chain(leaf_cert, root_cert)
        validate_leaf_cn(pod, leaf_cert)
        validate_leaf_dates(leaf_cert, leaf_json)

        save_cert(f"{service_name}.pem", [leaf_cert])
        save_key(f"{service_name}.key", leaf_key)

        pub = envoy_config.public_listener
        validate_listener_chain(pub.certificates, pub.private_key, pub.ca_certificates, leaf_cert, root_cert)
        validate_conn(pub.bind_address, pub.bind_port, leaf_cert, leaf_key, root_cert, openssl)

        for upstream_name, upstream_port in pod.upstreams:
            validate_upstream_chain(envoy_config.upstream(upstream_name), leaf_cert, root_cert)
            validate_downstream_config(envoy_config.downstream(upstream_name), upstream_name, upstream_port)

    if clean_openssl:
        openssl.delete()
    else:
        info('Leaving OpenSSL pod running')

    section('Compiling results...')
    color_assert(groovy, 'One or more errors were found.', 'Everything is groovy!')
