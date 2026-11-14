"""PKI locale : autorité de certification, certificats utilisateurs, vérification."""
import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

def _key_usage(ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True, content_commitment=not ca,
        key_encipherment=False, data_encipherment=False, key_agreement=False,
        key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False)

def create_ca(common_name="SecureShare Local CA", days=3650):
    """Crée une AC racine auto-signée (clé ECDSA P-256)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(_name(common_name)).issuer_name(_name(common_name))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(_key_usage(ca=True), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert

def load_or_create_ca(pki_dir):
    """Charge l'AC locale, ou la crée au premier lancement."""
    key_path = os.path.join(pki_dir, "ca.key")
    crt_path = os.path.join(pki_dir, "ca.crt")
    if os.path.exists(key_path) and os.path.exists(crt_path):
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(crt_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert
    key, cert = create_ca()
    with open(key_path, "wb") as f:  # VULNERABILITE : clé de l'AC non chiffrée
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert

def issue_user_cert(username, ca_key, ca_cert, not_before=None, not_after=None):
    """Émet un certificat pour un utilisateur. Retourne (clé privée PEM, certificat PEM)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(_name(username)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before or now - datetime.timedelta(minutes=1))
            .not_valid_after(not_after or now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(ca=False), critical=True)
            .sign(ca_key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())  # VULNERABILITE
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)

def verify_certificate(cert_pem, ca_cert, expected_cn):
    """Vérifie signature de l'AC, validité, usage de clé et identité. Retourne (ok, message explicite)."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError:
        return False, "Certificat illisible ou falsifié"
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature):
        return False, ("Certificat refusé (non approuvé) : non signé par notre AC "
                       "(AC inconnue ou certificat falsifié)")
    now = _now()
    if now > cert.not_valid_after_utc:
        return False, "Certificat refusé : expiré le %s" % cert.not_valid_after_utc.date()
    if now < cert.not_valid_before_utc:
        return False, "Certificat refusé : pas encore valide"
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.digital_signature:
        return False, "Certificat refusé : usage de clé incorrect"
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        return False, "Certificat refusé : il ne correspond pas à l'utilisateur"
    return True, "Certificat valide (émis par %s, expire le %s)" % (
        ca_cert.subject.rfc4514_string(), cert.not_valid_after_utc.date())
