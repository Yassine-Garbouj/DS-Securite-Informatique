"""Signature ECDSA P-256 / SHA-256 de l'empreinte d'un fichier."""
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def message_for(file_id: int, sha256_hex: str) -> bytes:
    """Message signé : version | identifiant | empreinte (évite le rejeu sur un autre fichier)."""
    return ("v1|%d|%s" % (file_id, sha256_hex)).encode()


def sign(private_key_pem: bytes, message: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    return key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(cert_pem: bytes, signature: bytes, message: bytes) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        cert.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
