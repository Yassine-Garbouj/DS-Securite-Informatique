"""Remet le projet à zéro : base de données, fichiers chiffrés, et (option) l'AC locale.

Usage :
    python reset_db.py          # vide la base et les fichiers chiffrés
    python reset_db.py --pki    # vide aussi l'AC locale (ca.key, ca.crt)
"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "data", "app.db")
STORAGE_DIR = os.path.join(BASE, "storage")
PKI_DIR = os.path.join(BASE, "pki")


def remove(path):
    try:
        os.remove(path)
        print("supprimé :", os.path.relpath(path, BASE))
    except FileNotFoundError:
        pass
    except PermissionError:
        print("ERREUR : %s est utilisé. Arrêtez le serveur (Ctrl+C) puis relancez." % path)
        sys.exit(1)


# 1. Base de données SQLite (recréée automatiquement au prochain lancement)
remove(DB_PATH)

# 2. Fichiers chiffrés déposés
if os.path.isdir(STORAGE_DIR):
    for name in os.listdir(STORAGE_DIR):
        full = os.path.join(STORAGE_DIR, name)
        if os.path.isfile(full):
            remove(full)

# 3. AC locale (optionnel) : ne supprime que ca.key et ca.crt
if "--pki" in sys.argv:
    for name in ("ca.key", "ca.crt"):
        remove(os.path.join(PKI_DIR, name))

print("Base remise à zéro. Relancez : python run.py")