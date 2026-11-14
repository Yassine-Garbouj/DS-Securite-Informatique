"""Chiffrement AES-256-GCM avec clé de fichier enveloppée par une clé maître."""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(data: bytes, aad: bytes, master_key: bytes):
    """Retourne (chiffré, nonce, clé de fichier enveloppée).

    - clé de fichier aléatoire de 256 bits, unique par fichier
    - nonce aléatoire de 96 bits, unique par chiffrement
    - AAD : lie le chiffré à son fichier et à son propriétaire
    - la clé de fichier est chiffrée (key wrapping) par la clé maître
    """
    file_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(file_key).encrypt(nonce, data, aad)
    wrap_nonce = os.urandom(12)
    wrapped = wrap_nonce + AESGCM(master_key).encrypt(wrap_nonce, file_key, None)
    return ciphertext, nonce, wrapped


def decrypt_file(ciphertext: bytes, nonce: bytes, wrapped: bytes,
                 aad: bytes, master_key: bytes) -> bytes:
    """Déchiffre. Lève cryptography.exceptions.InvalidTag si le chiffré est altéré."""
    wrap_nonce, wrapped_key = wrapped[:12], wrapped[12:]
    file_key = AESGCM(master_key).decrypt(wrap_nonce, wrapped_key, None)
    return AESGCM(file_key).decrypt(nonce, ciphertext, aad)
