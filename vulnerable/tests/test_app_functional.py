"""Scénarios fonctionnels Alice / Bob."""
import os
from conftest import upload


def test_alice_uploads_and_downloads_intact_file(make_client):
    alice = make_client("alice")
    upload(alice, content=b"contrat")
    r = alice.get("/download/1")
    assert r.status_code == 200 and r.data == b"contrat"


def test_file_is_encrypted_on_disk(app, make_client):
    alice = make_client("alice")
    upload(alice, content=b"TEXTE-CONFIDENTIEL")
    raw = open(os.path.join(app.config["STORAGE_DIR"], "contrat.pdf.enc"), "rb").read()
    assert b"TEXTE-CONFIDENTIEL" not in raw


def test_share_with_bob_and_verify(make_client):
    alice, bob = make_client("alice"), make_client("bob")
    upload(alice)
    alice.post("/share/1", data={"recipient": "bob"})
    page = bob.get("/files").get_data(as_text=True)
    assert "contrat.pdf" in page
    report = bob.get("/verify/1").get_data(as_text=True)
    assert "Intégrité vérifiée" in report and "Signature valide" in report


def test_modified_encrypted_file_detected(app, make_client):
    alice = make_client("alice")
    upload(alice)
    path = os.path.join(app.config["STORAGE_DIR"], "contrat.pdf.enc")
    raw = bytearray(open(path, "rb").read())
    raw[0] ^= 1
    open(path, "wb").write(bytes(raw))
    page = alice.get("/download/1").get_data(as_text=True)
    assert "Échec de vérification" in page


def test_hash_modified_in_database_detected(app, make_client):
    import sqlite3
    alice = make_client("alice")
    upload(alice)
    con = sqlite3.connect(app.config["DB_PATH"])
    con.execute("UPDATE files SET sha256 = ? WHERE id = 1", ("0" * 64,))
    con.commit()
    assert "Échec de vérification" in alice.get("/verify/1").get_data(as_text=True)


def test_local_file_comparison(make_client):
    import io
    alice = make_client("alice")
    upload(alice, content=b"abc")
    r = alice.post("/verify_local/1", data={"file": (io.BytesIO(b"abd"), "x.pdf")},
                   content_type="multipart/form-data", follow_redirects=True)
    assert "DIFFÉRENT" in r.get_data(as_text=True)
