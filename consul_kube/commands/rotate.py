import click
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from consul_kube.lib.color import debug, info, color_assert
from consul_kube.lib.kube import ConsulApiClient
from consul_kube.lib.x509 import compare_certs, save_cert, save_key


def generate_ecdsa_key() -> crypto.PKey:
    debug('Generating EC params')
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    key_pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=NoEncryption())
    return crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)


def generate_ca_root(serial_number: int, trust_domain: str, public_key: crypto.PKey) -> crypto.X509:
    debug('Generating self-signed CA certificate')
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(serial_number)
    cert.set_pubkey(public_key)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 86400)
    setattr(cert.get_subject(), 'CN', f'Consul CA {serial_number}')
    cert.set_issuer(cert.get_subject())
    spiffe_uri = f'URI:spiffe://{trust_domain}'.encode('utf-8')
    cert.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
        crypto.X509Extension(b'keyUsage', True, b'digitalSignature, cRLSign, keyCertSign'),
        crypto.X509Extension(b'subjectAltName', False, spiffe_uri)
    ])
    cert.add_extensions([crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert)])
    cert.add_extensions([crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always,issuer', issuer=cert)])
    # noinspection PyTypeChecker
    cert.sign(public_key, "sha256")

    return cert


# noinspection PyUnusedLocal
def rotate_command(ctx: click.Context) -> None:  # pylint: disable=W0613
    debug('Looking up existing CA serial number')
    consul_api = ConsulApiClient()
    root_cert, api_response = consul_api.active_ca_root_cert

    trust_domain = api_response['TrustDomain']
    old_serial = root_cert.get_serial_number()
    info(f'Current CA serial number is {old_serial}')

    key = generate_ecdsa_key()
    cert = generate_ca_root(old_serial + 1, trust_domain, key)
    save_cert('new_root.crt', [cert])
    save_key('new_root.key', key)

    debug('Sending new CA cert to Consul')
    result_body, response_code, _ = consul_api.update_config(key, cert)
    color_assert(response_code == 200, f'Unexpected HTTP return code from server: {response_code}({result_body})',
                 'Consul responded with 200 OK')

    debug('Confirming new CA cert with Consul')
    new_root, _ = consul_api.active_ca_root_cert
    color_assert(compare_certs(new_root, cert),
                 'Cert returned by Consul does not match what we just uploaded',
                 'Cert returned by Consul matches our new cert')

    info(f'New root CA with serial {new_root.get_serial_number()} is now live')
