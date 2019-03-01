from OpenSSL import crypto
from typing import Optional, Tuple, List
from datetime import datetime
from io import StringIO

from consul_kube.lib.color import write_certs, debug


CERT_DATETIME_FORMAT = '%Y%m%d%H%M%SZ'


def serial(cert: crypto.X509) -> str:
    sn = hex(cert.get_serial_number())[2:]
    sn = sn.rjust(4, '0')
    return sn


def cert_from_pem(pem_text: bytes) -> crypto.X509:
    return crypto.load_certificate(crypto.FILETYPE_PEM, pem_text)


def cert_to_pem(cert: crypto.X509) -> bytes:
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)


def pkey_from_pem(pem_text: bytes) -> crypto.PKey:
    return crypto.load_privatekey(crypto.FILETYPE_PEM, pem_text)


def pkey_to_pem(pkey: crypto.PKey) -> bytes:
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)


def load_certs(stream: StringIO) -> List[crypto.X509]:
    certs = []
    pem_text = ''
    wanted = False
    for line in stream:
        if line == '-----BEGIN CERTIFICATE-----\n':
            wanted = True
            pem_text = line
        elif line == '-----END CERTIFICATE-----\n':
            pem_text += line
            wanted = False
            certs.append(cert_from_pem(pem_text))
        elif wanted:
            pem_text += line

    if len(certs) == 0:
        raise RuntimeError('No PEM certificates found in stream')
    return certs


def validate_cert(cert: crypto.X509, *args) -> Optional[str]:
    store = crypto.X509Store()
    for cert in args:  # type: crypto.X509
        store.add_cert(cert)

    store_ctx = crypto.X509StoreContext(store, cert)

    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError as e:
        return e.args[0][2]
    else:
        return None


def get_valid_times(cert: crypto.X509) -> Tuple[datetime, datetime]:
    before = convert_cert_dt(cert.get_notBefore())
    after = convert_cert_dt(cert.get_notAfter())
    return before, after


def convert_cert_dt(dt: bytes) -> datetime:
    return datetime.strptime(dt.decode('utf-8'), CERT_DATETIME_FORMAT)


# noinspection PyTypeChecker
def cert_digest(cert: crypto.X509) -> str:
    return cert.digest("md5").decode('utf-8')


def compare_certs(a: crypto.X509, b: crypto.X509) -> bool:
    return cert_digest(a) == cert_digest(b)


def cert_in_list(a: crypto.X509, *args: crypto.X509) -> bool:
    for b in args:
        if cert_digest(a) == cert_digest(b):
            return True
    else:
        return False


def get_subject_cn(cert: crypto.X509) -> Optional[str]:
    sub = cert.get_subject()  # type crypto.X509Name
    for key, val in sub.get_components():
        if key == b'CN':
            return val.decode('utf-8')
    else:
        return None


def extract_cert(wall_of_text: str) -> List[crypto.X509]:
    return load_certs(StringIO(wall_of_text))


def get_subject_alt_name(cert: crypto.X509) -> Optional[bytes]:
    for i in range(0, cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b'subjectAltName':
            return ext.get_data()
    else:
        return None


def save_cert(filename: str, certs: List[crypto.X509]) -> None:
    if write_certs:
        debug(f'Writing certificate to file {filename}')
        with open(filename, "wb") as f:
            for cert in certs:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


def save_key(filename: str, key: crypto.PKey) -> None:
    if write_certs:
        debug(f'Writing private key to file {filename}')
        with open(filename, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
