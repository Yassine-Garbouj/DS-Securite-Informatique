"""Configuration de la VERSION 1 (volontairement vulnérable)."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# VULNERABILITE : clé secrète Flask faible et écrite dans le code
SECRET_KEY = "secret"

DB_PATH = os.path.join(BASE_DIR, "data", "app.db")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
PKI_DIR = os.path.join(BASE_DIR, "pki")

# VULNERABILITE : clé maître AES-256 écrite en dur dans le code source
MASTER_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
