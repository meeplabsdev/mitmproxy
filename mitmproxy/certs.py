import contextlib
import datetime
import ipaddress
import logging
import os
import sys
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from typing import NewType
from typing import Optional
from typing import Union

import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ExtendedKeyUsageOID
from cryptography.x509 import NameOID

from mitmproxy.coretypes import serializable

logger = logging.getLogger(__name__)

# Default expiry must not be too long: https://github.com/mitmproxy/mitmproxy/issues/815
CA_EXPIRY = datetime.timedelta(days=10 * 365)
CERT_EXPIRY = datetime.timedelta(days=365)

# Generated with "openssl dhparam". It's too slow to generate this on startup.
DEFAULT_DHPARAM = b"""
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAyT6LzpwVFS3gryIo29J5icvgxCnCebcdSe/NHMkD8dKJf8suFCg3
O2+dguLakSVif/t6dhImxInJk230HmfC8q93hdcg/j8rLGJYDKu3ik6H//BAHKIv
j5O9yjU3rXCfmVJQic2Nne39sg3CreAepEts2TvYHhVv3TEAzEqCtOuTjgDv0ntJ
Gwpj+BJBRQGG9NvprX1YGJ7WOFBP/hWU7d6tgvE6Xa7T/u9QIKpYHMIkcN/l3ZFB
chZEqVlyrcngtSXCROTPcDOQ6Q8QzhaBJS+Z6rcsd7X+haiQqvoFcmaJ08Ks6LQC
ZIL2EtYJw8V8z7C0igVEBIADZBI6OTbuuhDwRw//zU1uq52Oc48CIZlGxTYG/Evq
o9EWAXUYVzWkDSTeBH1r4z/qLPE2cnhtMxbFxuvK53jGB0emy2y1Ei6IhKshJ5qX
IB/aE7SSHyQ3MDHHkCmQJCsOd4Mo26YX61NZ+n501XjqpCBQ2+DfZCBh8Va2wDyv
A2Ryg9SUz8j0AXViRNMJgJrr446yro/FuJZwnQcO3WQnXeqSBnURqKjmqkeFP+d8
6mk2tqJaY507lRNqtGlLnj7f5RNoBFJDCLBNurVgfvq9TCVWKDIFD4vZRjCrnl6I
rD693XKIHUCWOjMh1if6omGXKHH40QuME2gNa50+YPn1iYDl88uDbbMCAQI=
-----END DH PARAMETERS-----
"""


class Cert(serializable.Serializable):
    """Representation of a (TLS) certificate."""

    _cert: x509.Certificate

    def __init__(self, cert: x509.Certificate):
        assert isinstance(cert, x509.Certificate)
        self._cert = cert

    def __eq__(self, other):
        return self.fingerprint() == other.fingerprint()

    def __repr__(self):
        altnames = [str(x.value) for x in self.altnames]
        return f"<Cert(cn={self.cn!r}, altnames={altnames!r})>"

    def __hash__(self):
        return self._cert.__hash__()

    @classmethod
    def from_state(cls, state):
        return cls.from_pem(state)

    def get_state(self):
        return self.to_pem()

    def set_state(self, state):
        self._cert = x509.load_pem_x509_certificate(state)

    @classmethod
    def from_pem(cls, data: bytes) -> "Cert":
        cert = x509.load_pem_x509_certificate(data)  # type: ignore
        return cls(cert)

    def to_pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    @classmethod
    def from_pyopenssl(self, x509: OpenSSL.crypto.X509) -> "Cert":
        return Cert(x509.to_cryptography())

    def to_pyopenssl(self) -> OpenSSL.crypto.X509:
        return OpenSSL.crypto.X509.from_cryptography(self._cert)

    def public_key(self) -> CertificatePublicKeyTypes:
        return self._cert.public_key()

    def fingerprint(self) -> bytes:
        return self._cert.fingerprint(hashes.SHA256())

    @property
    def issuer(self) -> list[tuple[str, str]]:
        return _name_to_keyval(self._cert.issuer)

    @property
    def notbefore(self) -> datetime.datetime:
        try:
            # type definitions haven't caught up with new API yet.
            return self._cert.not_valid_before_utc  # type: ignore
        except AttributeError:  # pragma: no cover
            # cryptography < 42.0
            return self._cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    @property
    def notafter(self) -> datetime.datetime:
        try:
            return self._cert.not_valid_after_utc  # type: ignore
        except AttributeError:  # pragma: no cover
            return self._cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    def has_expired(self) -> bool:
        if sys.version_info < (3, 11):  # pragma: no cover
            return datetime.datetime.now(datetime.timezone.utc) > self.notafter
        return datetime.datetime.now(datetime.UTC) > self.notafter

    @property
    def subject(self) -> list[tuple[str, str]]:
        return _name_to_keyval(self._cert.subject)

    @property
    def serial(self) -> int:
        return self._cert.serial_number

    @property
    def is_ca(self) -> bool:
        constraints: x509.BasicConstraints
        try:
            constraints = self._cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            return constraints.ca
        except x509.ExtensionNotFound:
            return False

    @property
    def keyinfo(self) -> tuple[str, int]:
        public_key = self._cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA", public_key.key_size
        if isinstance(public_key, dsa.DSAPublicKey):
            return "DSA", public_key.key_size
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return f"EC ({public_key.curve.name})", public_key.key_size
        return (
            public_key.__class__.__name__.replace("PublicKey", "").replace("_", ""),
            getattr(public_key, "key_size", -1),
        )  # pragma: no cover

    @property
    def cn(self) -> str | None:
        attrs = self._cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if attrs:
            return cast(str, attrs[0].value)
        return None

    @property
    def organization(self) -> str | None:
        attrs = self._cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if attrs:
            return cast(str, attrs[0].value)
        return None

    @property
    def altnames(self) -> x509.GeneralNames:
        """
        Get all SubjectAlternativeName DNS altnames.
        """
        try:
            sans = self._cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return x509.GeneralNames([])
        else:
            return x509.GeneralNames(sans)


def _name_to_keyval(name: x509.Name) -> list[tuple[str, str]]:
    parts = []
    for attr in name:
        k = attr.rfc4514_string().partition("=")[0]
        v = cast(str, attr.value)
        parts.append((k, v))
    return parts


def create_ca(
    organization: str,
    common_name: str,
    key_size: int,
) -> tuple[rsa.RSAPrivateKeyWithSerialization, x509.Certificate]:
    now = datetime.datetime.now()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )  # type: ignore
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.subject_name(name)
    builder = builder.not_valid_before(now - datetime.timedelta(days=2))
    builder = builder.not_valid_after(now + CA_EXPIRY)
    builder = builder.issuer_name(name)
    builder = builder.public_key(private_key.public_key())
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())  # type: ignore
    return private_key, cert


def _fix_legacy_sans(sans: Iterable[x509.GeneralName] | list[str]) -> x509.GeneralNames:
    """
    SANs used to be a list of strings in mitmproxy 10.1 and below, but now they're a list of GeneralNames.
    This function converts the old format to the new one.
    """
    if isinstance(sans, x509.GeneralNames):
        return sans
    elif isinstance(sans, list) and len(sans) > 0 and isinstance(sans[0], str):  # pragma: no cover
        warnings.warn(
            "Passing SANs as a list of strings is deprecated.",
            DeprecationWarning,
            stacklevel=2,
        )

        ss: list[x509.GeneralName] = []
        for x in cast(list[str], sans):
            try:
                ip = ipaddress.ip_address(x)
            except ValueError:
                x = x.encode("idna").decode()
                ss.append(x509.DNSName(x))
            else:
                ss.append(x509.IPAddress(ip))
        return x509.GeneralNames(ss)
    else:
        return x509.GeneralNames(sans)


def dummy_cert(
    privkey: rsa.RSAPrivateKey,
    cacert: x509.Certificate,
    commonname: str | None,
    sans: Iterable[x509.GeneralName],
    organization: str | None = None,
) -> Cert:
    """
    Generates a dummy certificate.

    privkey: CA private key
    cacert: CA certificate
    commonname: Common name for the generated certificate.
    sans: A list of Subject Alternate Names.
    organization: Organization name for the generated certificate.

    Returns cert if operation succeeded, None if not.
    """
    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(cacert.subject)
    builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    builder = builder.public_key(cacert.public_key())

    now = datetime.datetime.now()
    builder = builder.not_valid_before(now - datetime.timedelta(days=2))
    builder = builder.not_valid_after(now + CERT_EXPIRY)

    subject = []
    is_valid_commonname = commonname is not None and len(commonname) < 64
    if is_valid_commonname:
        assert commonname is not None
        subject.append(x509.NameAttribute(NameOID.COMMON_NAME, commonname))
    if organization is not None:
        assert organization is not None
        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    builder = builder.subject_name(x509.Name(subject))
    builder = builder.serial_number(x509.random_serial_number())

    # RFC 5280 §4.2.1.6: subjectAltName is critical if subject is empty.
    builder = builder.add_extension(
        x509.SubjectAlternativeName(_fix_legacy_sans(sans)),
        critical=not is_valid_commonname,
    )

    # https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()),
        critical=False,
    )
    # If CA and leaf cert have the same Subject Key Identifier, SChannel breaks in funny ways,
    # see https://github.com/mitmproxy/mitmproxy/issues/6494.
    # https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2 states
    # that SKI is optional for the leaf cert, so we skip that.

    cert = builder.sign(private_key=privkey, algorithm=hashes.SHA256())  # type: ignore
    return Cert(cert)


@dataclass(frozen=True)
class CertStoreEntry:
    cert: Cert
    privatekey: rsa.RSAPrivateKey
    chain_file: Path | None
    chain_certs: list[Cert]


TCustomCertId = str  # manually provided certs (e.g. mitmproxy's --certs)
TGeneratedCertId = tuple[Optional[str], x509.GeneralNames]  # (common_name, sans)
TCertId = Union[TCustomCertId, TGeneratedCertId]

DHParams = NewType("DHParams", bytes)


class CertStore:
    """
    Implements an in-memory certificate store.
    """

    STORE_CAP = 100
    default_privatekey: rsa.RSAPrivateKey
    default_ca: Cert
    default_chain_file: Path | None
    default_chain_certs: list[Cert]
    dhparams: DHParams
    certs: dict[TCertId, CertStoreEntry]
    expire_queue: list[CertStoreEntry]

    def __init__(
        self,
        default_privatekey: rsa.RSAPrivateKey,
        default_ca: Cert,
        default_chain_file: Path | None,
        dhparams: DHParams,
    ):
        self.default_privatekey = default_privatekey
        self.default_ca = default_ca
        self.default_chain_file = default_chain_file
        self.default_chain_certs = [Cert(c) for c in x509.load_pem_x509_certificates(self.default_chain_file.read_bytes())] if self.default_chain_file else [default_ca]
        self.dhparams = dhparams
        self.certs = {}
        self.expire_queue = []

    def expire(self, entry: CertStoreEntry) -> None:
        self.expire_queue.append(entry)
        if len(self.expire_queue) > self.STORE_CAP:
            d = self.expire_queue.pop(0)
            self.certs = {k: v for k, v in self.certs.items() if v != d}

    @staticmethod
    def load_dhparam(path: Path) -> DHParams:
        # mitmproxy<=0.10 doesn't generate a dhparam file.
        # Create it now if necessary.
        if not path.exists():
            path.write_bytes(DEFAULT_DHPARAM)

        # we could use cryptography for this, but it's unclear how to convert cryptography's object to pyOpenSSL's
        # expected format.
        bio = OpenSSL.SSL._lib.BIO_new_file(  # type: ignore
            str(path).encode(sys.getfilesystemencoding()), b"r"
        )
        if bio != OpenSSL.SSL._ffi.NULL:  # type: ignore
            bio = OpenSSL.SSL._ffi.gc(bio, OpenSSL.SSL._lib.BIO_free)  # type: ignore
            dh = OpenSSL.SSL._lib.PEM_read_bio_DHparams(  # type: ignore
                bio,
                OpenSSL.SSL._ffi.NULL,  # type: ignore
                OpenSSL.SSL._ffi.NULL,  # type: ignore
                OpenSSL.SSL._ffi.NULL,  # type: ignore
            )
            dh = OpenSSL.SSL._ffi.gc(dh, OpenSSL.SSL._lib.DH_free)  # type: ignore
            return dh
        raise RuntimeError("Error loading DH Params.")  # pragma: no cover

    @classmethod
    def from_store(
        cls,
        path: Path | str,
        basename: str,
        key_size: int,
        organization: Optional[str] = None,
        common_name: Optional[str] = None,
        passphrase: bytes | None = None,
    ) -> "CertStore":
        path = Path(path)
        ca_file = path / f"{basename}-ca.pem"
        dhparam_file = path / f"{basename}-dhparam.pem"
        if not ca_file.exists():
            cls.create_store(path, basename, key_size, organization, common_name)
        return cls.from_files(ca_file, dhparam_file, passphrase)

    @classmethod
    def from_files(cls, ca_file: Path, dhparam_file: Path, passphrase: bytes | None = None) -> "CertStore":
        raw = ca_file.read_bytes()
        key = load_pem_private_key(raw, passphrase)
        dh = cls.load_dhparam(dhparam_file)
        certs = x509.load_pem_x509_certificates(raw)
        ca = Cert(certs[0])
        if len(certs) > 1:
            chain_file: Path | None = ca_file
        else:
            chain_file = None
        return cls(key, ca, chain_file, dh)

    @staticmethod
    @contextlib.contextmanager
    def umask_secret():
        """
        Context to temporarily set umask to its original value bitor 0o77.
        Useful when writing private keys to disk so that only the owner
        will be able to read them.
        """
        original_umask = os.umask(0)
        os.umask(original_umask | 0o77)
        try:
            yield
        finally:
            os.umask(original_umask)

    @staticmethod
    def create_store(
        path: Path,
        basename: str,
        key_size: int,
        organization: Optional[str] = None,
        common_name: Optional[str] = None,
    ) -> None:
        path.mkdir(parents=True, exist_ok=True)

        organization = organization or basename
        common_name = common_name or basename

        key: rsa.RSAPrivateKeyWithSerialization
        ca: x509.Certificate
        key, ca = create_ca(organization=organization, common_name=common_name, key_size=key_size)

        # Dump the CA plus private key.
        with CertStore.umask_secret():
            # PEM format
            (path / f"{basename}-ca.pem").write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                + ca.public_bytes(serialization.Encoding.PEM)
            )

            # PKCS12 format for Windows devices
            (path / f"{basename}-ca.p12").write_bytes(
                pkcs12.serialize_key_and_certificates(  # type: ignore
                    name=basename.encode(),
                    key=key,
                    cert=ca,
                    cas=None,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Dump the certificate in PEM format
        pem_cert = ca.public_bytes(serialization.Encoding.PEM)
        (path / f"{basename}-ca-cert.pem").write_bytes(pem_cert)
        # Create a .cer file with the same contents for Android
        (path / f"{basename}-ca-cert.cer").write_bytes(pem_cert)

        # Dump the certificate in PKCS12 format for Windows devices
        (path / f"{basename}-ca-cert.p12").write_bytes(
            pkcs12.serialize_key_and_certificates(
                name=basename.encode(),
                key=None,  # type: ignore
                cert=ca,
                cas=None,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        (path / f"{basename}-dhparam.pem").write_bytes(DEFAULT_DHPARAM)

    def add_cert_file(self, spec: str, path: Path, passphrase: bytes | None = None) -> None:
        raw = path.read_bytes()
        cert = Cert.from_pem(raw)
        try:
            private_key = load_pem_private_key(raw, password=passphrase)
        except ValueError as e:
            private_key = self.default_privatekey
            if cert.public_key() != private_key.public_key():
                raise ValueError(f'Unable to find private key in "{path.absolute()}": {e}') from e
        else:
            if cert.public_key() != private_key.public_key():
                raise ValueError(f'Private and public keys in "{path.absolute()}" do not match:\n{cert.public_key()=}\n{private_key.public_key()=}')

        try:
            chain = [Cert(x) for x in x509.load_pem_x509_certificates(raw)]
        except ValueError as e:
            logger.warning(f"Failed to read certificate chain: {e}")
            chain = [cert]

        if cert.is_ca:
            logger.warning(f'"{path.absolute()}" is a certificate authority and not a leaf certificate. This indicates a misconfiguration, see https://docs.mitmproxy.org/stable/concepts-certificates/.')

        self.add_cert(CertStoreEntry(cert, private_key, path, chain), spec)

    def add_cert(self, entry: CertStoreEntry, *names: str) -> None:
        """
        Adds a cert to the certstore. We register the CN in the cert plus
        any SANs, and also the list of names provided as an argument.
        """
        if entry.cert.cn:
            self.certs[entry.cert.cn] = entry
        for i in entry.cert.altnames:
            self.certs[str(i.value)] = entry
        for i in names:
            self.certs[i] = entry

    @staticmethod
    def asterisk_forms(dn: str | x509.GeneralName) -> list[str]:
        """
        Return all asterisk forms for a domain. For example, for www.example.com this will return
        [b"www.example.com", b"*.example.com", b"*.com"]. The single wildcard "*" is omitted.
        """
        if isinstance(dn, str):
            parts = dn.split(".")
            ret = [dn]
            for i in range(1, len(parts)):
                ret.append("*." + ".".join(parts[i:]))
            return ret
        elif isinstance(dn, x509.DNSName):
            return CertStore.asterisk_forms(dn.value)
        else:
            return [str(dn.value)]

    def get_cert(
        self,
        commonname: str | None,
        sans: Iterable[x509.GeneralName],
        organization: str | None = None,
    ) -> CertStoreEntry:
        """
        commonname: Common name for the generated certificate. Must be a
        valid, plain-ASCII, IDNA-encoded domain name.

        sans: A list of Subject Alternate Names.

        organization: Organization name for the generated certificate.
        """
        sans = _fix_legacy_sans(sans)

        potential_keys: list[TCertId] = []
        if commonname:
            potential_keys.extend(self.asterisk_forms(commonname))
        for s in sans:
            potential_keys.extend(self.asterisk_forms(s))
        potential_keys.append("*")
        potential_keys.append((commonname, sans))

        name = next(filter(lambda key: key in self.certs, potential_keys), None)
        if name:
            entry = self.certs[name]
        else:
            entry = CertStoreEntry(
                cert=dummy_cert(
                    self.default_privatekey,
                    self.default_ca._cert,
                    commonname,
                    sans,
                    organization,
                ),
                privatekey=self.default_privatekey,
                chain_file=self.default_chain_file,
                chain_certs=self.default_chain_certs,
            )
            self.certs[(commonname, sans)] = entry
            self.expire(entry)

        return entry


def load_pem_private_key(data: bytes, password: bytes | None) -> rsa.RSAPrivateKey:
    """
    like cryptography's load_pem_private_key, but silently falls back to not using a password
    if the private key is unencrypted.
    """
    try:
        return serialization.load_pem_private_key(data, password)  # type: ignore
    except TypeError:
        if password is not None:
            return load_pem_private_key(data, None)
        raise
