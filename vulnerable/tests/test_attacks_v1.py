"""PREUVES D'ATTAQUES sur la version 1. Chaque test PASSE si l'attaque RÉUSSIT.
En version 2, les mêmes scénarios doivent ÉCHOUER (on inversera les assertions)."""
import io
import os
from conftest import upload
from app.db import get_db


def test_V1_sql_injection_login_bypass(make_client):
    make_client("alice")
    attacker = make_client()
    attacker.post("/login", data={"username": "alice' --", "password": "n_importe_quoi"})
    assert "Mes fichiers" in attacker.get("/files").get_data(as_text=True)


def test_V1_sql_injection_dump_password_hashes(make_client):
    alice = make_client("alice")
    payload = "zzz%' UNION SELECT id, username || ':' || password_hash, 0 FROM users --"
    page = alice.get("/search", query_string={"q": payload}).get_data(as_text=True)
    assert "alice:" in page  # hash MD5 de la table users exposé


def test_V1_reflected_xss(make_client):
    alice = make_client("alice")
    page = alice.get("/search", query_string={"q": "<script>alert(1)</script>"}).get_data(as_text=True)
    assert "<script>alert(1)</script>" in page


def test_V1_stored_xss_in_filename(make_client, app):
    alice = make_client("alice")
    name = "<img src=x onerror=alert(1)>.pdf"
    if os.name == "nt":
        # Windows forbids angle brackets in filesystem paths; seed the same stored value.
        with app.app_context():
            db = get_db()
            owner_id = db.execute(
                "SELECT id FROM users WHERE username = ?", ("alice",)).fetchone()["id"]
            db.execute(
                "INSERT INTO files(owner_id, original_name, stored_name, size, sha256) "
                "VALUES (?, ?, ?, 0, '')", (owner_id, name, name + ".enc"))
            db.commit()
    else:
        upload(alice, name=name)
    assert "<img src=x onerror=alert(1)>" in alice.get("/files").get_data(as_text=True)


def test_V1_idor_read_other_users_file(make_client):
    alice, mallory = make_client("alice"), make_client("mallory")
    upload(alice, content=b"contrat d'Alice")
    r = mallory.get("/download/1")  # Mallory n'a aucun droit
    assert r.status_code == 200 and r.data == b"contrat d'Alice"


def test_V1_csrf_share_without_token(make_client):
    alice, _ = make_client("alice"), make_client("bob")
    upload(alice)
    r = alice.post("/share/1", data={"recipient": "bob"})  # aucun jeton CSRF exigé
    assert r.status_code == 302


def test_V1_share_someone_elses_file(make_client):
    alice, mallory = make_client("alice"), make_client("mallory")
    upload(alice)
    mallory.post("/share/1", data={"recipient": "mallory"})  # pas de contrôle de propriété
    assert "contrat.pdf" in mallory.get("/files").get_data(as_text=True)


def test_V1_brute_force_no_lockout(make_client):
    make_client("alice")
    attacker = make_client()
    for i in range(20):
        attacker.post("/login", data={"username": "alice", "password": "faux%d" % i})
    attacker.post("/login", data={"username": "alice", "password": "Passw0rd!"})
    assert "Mes fichiers" in attacker.get("/files").get_data(as_text=True)


def test_V1_user_enumeration(make_client):
    make_client("alice")
    c = make_client()
    a = c.post("/login", data={"username": "alice", "password": "x"}).get_data(as_text=True)
    b = c.post("/login", data={"username": "inconnu", "password": "x"}).get_data(as_text=True)
    assert "Mot de passe incorrect" in a and "Utilisateur inconnu" in b


def test_V1_audit_log_public(make_client):
    make_client("alice")
    assert "inscription" in make_client().get("/audit").get_data(as_text=True)
