from OpenSSL.crypto import *
from typing import Optional, Tuple, List
from datetime import datetime
from io import StringIO

from consul_kube.lib import write_certs, debug


CERT_DATETIME_FORMAT = '%Y%m%d%H%M%SZ'


def serial(cert: X509) -> str:
    sn = hex(cert.get_serial_number())[2:]
    sn = sn.rjust(4, '0')
    return sn


def cert_from_pem(pem_text: bytes) -> X509:
    return load_certificate(FILETYPE_PEM, pem_text)


def cert_to_pem(cert: X509) -> bytes:
    return dump_certificate(FILETYPE_PEM, cert)


def pkey_from_pem(pem_text: bytes) -> PKey:
    return load_privatekey(FILETYPE_PEM, pem_text)


def pkey_to_pem(pkey: PKey) -> bytes:
    return dump_privatekey(FILETYPE_PEM, pkey)


def load_certs(stream: StringIO) -> List[X509]:
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


def validate_cert(cert: X509, *args) -> Optional[str]:
    store = X509Store()
    for cert in args:  # type: X509
        store.add_cert(cert)

    store_ctx = X509StoreContext(store, cert)

    try:
        store_ctx.verify_certificate()
    except X509StoreContextError as e:
        return e.args[0][2]
    else:
        return None


def get_valid_times(cert: X509) -> Tuple[datetime, datetime]:
    before = convert_cert_dt(cert.get_notBefore())
    after = convert_cert_dt(cert.get_notAfter())
    return before, after


def convert_cert_dt(dt: bytes) -> datetime:
    return datetime.strptime(dt.decode('utf-8'), CERT_DATETIME_FORMAT)


# noinspection PyTypeChecker
def cert_digest(cert: X509) -> str:
    return cert.digest("md5").decode('utf-8')


def compare_certs(a: X509, b: X509) -> bool:
    return cert_digest(a) == cert_digest(b)


def cert_in_list(a: X509, *args: X509) -> bool:
    for b in args:
        if cert_digest(a) == cert_digest(b):
            return True
    else:
        return False


def get_subject_cn(cert: X509) -> Optional[str]:
    sub = cert.get_subject()  # type X509Name
    for key, val in sub.get_components():
        if key == b'CN':
            return val.decode('utf-8')
    else:
        return None


def extract_cert(wall_of_text: str) -> List[X509]:
    return load_certs(StringIO(wall_of_text))
    # return cert_from_pem(extract_pem(wall_of_text).encode('utf-8'))


def get_subject_alt_name(cert: X509) -> Optional[bytes]:
    for i in range(0, cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name() == b'subjectAltName':
            return ext.get_data()
    else:
        return None


def save_cert(filename: str, certs: List[X509]) -> None:
    if write_certs:
        debug(f'Writing certificate to file {filename}')
        with open(filename, "wb") as f:
            for cert in certs:
                f.write(dump_certificate(FILETYPE_PEM, cert))


def save_key(filename: str, key: PKey) -> None:
    if write_certs:
        debug(f'Writing private key to file {filename}')
        with open(filename, "wb") as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
