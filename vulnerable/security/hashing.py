import hashlib


def sha256_hex(data: bytes) -> str:
    """Empreinte SHA-256 d'un contenu (intégrité)."""
    return hashlib.sha256(data).hexdigest()


def weak_password_hash(password: str) -> str:
    """VULNERABILITE : MD5 sans sel, rapide à casser (corrigé en V2 par Argon2id)."""
    return hashlib.md5(password.encode()).hexdigest()
