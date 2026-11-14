"""Tests unitaires des modules cryptographiques (matrice de tests du projet)."""
import datetime
import pytest
from cryptography.exceptions import InvalidTag

from security import certs, crypto, signature

MASTER = bytes(range(32))


def test_aes_gcm_roundtrip():
    ct, nonce, wrapped = crypto.encrypt_file(b"secret", b"1|1", MASTER)
    assert crypto.decrypt_file(ct, nonce, wrapped, b"1|1", MASTER) == b"secret"


def test_aes_gcm_detects_modified_byte():
    ct, nonce, wrapped = crypto.encrypt_file(b"secret data", b"1|1", MASTER)
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(InvalidTag):
        crypto.decrypt_file(tampered, nonce, wrapped, b"1|1", MASTER)


def test_aes_gcm_wrong_aad_rejected():
    ct, nonce, wrapped = crypto.encrypt_file(b"secret", b"1|1", MASTER)
    with pytest.raises(InvalidTag):
        crypto.decrypt_file(ct, nonce, wrapped, b"2|1", MASTER)


def test_nonce_is_unique():
    nonces = {crypto.encrypt_file(b"x", b"a", MASTER)[1] for _ in range(50)}
    assert len(nonces) == 50


def test_valid_certificate_accepted(tmp_path):
    ca_key, ca_cert = certs.create_ca()
    _, cert = certs.issue_user_cert("alice", ca_key, ca_cert)
    ok, msg = certs.verify_certificate(cert, ca_cert, "alice")
    assert ok, msg


def test_expired_certificate_rejected():
    ca_key, ca_cert = certs.create_ca()
    now = datetime.datetime.now(datetime.timezone.utc)
    _, cert = certs.issue_user_cert("alice", ca_key, ca_cert,
                                    not_before=now - datetime.timedelta(days=10),
                                    not_after=now - datetime.timedelta(days=1))
    ok, msg = certs.verify_certificate(cert, ca_cert, "alice")
    assert not ok and "expiré" in msg


def test_unknown_ca_rejected():
    ca_key, ca_cert = certs.create_ca()
    rogue_key, rogue_cert = certs.create_ca("Fausse AC")
    _, cert = certs.issue_user_cert("alice", rogue_key, rogue_cert)
    ok, msg = certs.verify_certificate(cert, ca_cert, "alice")
    assert not ok and "non approuvé" in msg


def test_certificate_wrong_user_rejected():
    ca_key, ca_cert = certs.create_ca()
    _, cert = certs.issue_user_cert("alice", ca_key, ca_cert)
    ok, msg = certs.verify_certificate(cert, ca_cert, "bob")
    assert not ok


def test_signature_valid_and_other_user_rejected():
    ca_key, ca_cert = certs.create_ca()
    alice_key, alice_cert = certs.issue_user_cert("alice", ca_key, ca_cert)
    bob_key, bob_cert = certs.issue_user_cert("bob", ca_key, ca_cert)
    msg = signature.message_for(1, "ab" * 32)
    sig = signature.sign(alice_key, msg)
    assert signature.verify(alice_cert, sig, msg)
    assert not signature.verify(bob_cert, sig, msg)                 # signature d'un autre utilisateur
    assert not signature.verify(alice_cert, sig, signature.message_for(1, "cd" * 32))  # empreinte modifiée
