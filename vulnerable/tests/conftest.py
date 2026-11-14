import io
import pytest
from app import create_app


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "DB_PATH": str(tmp_path / "app.db"),
        "STORAGE_DIR": str(tmp_path / "storage"),
        "PKI_DIR": str(tmp_path / "pki"),
    })


@pytest.fixture
def make_client(app):
    """Fabrique un client HTTP indépendant (un par utilisateur)."""
    def _make(username=None, password="Passw0rd!"):
        c = app.test_client()
        if username:
            c.post("/register", data={"username": username, "email": username + "@test.local",
                                      "password": password})
            c.post("/login", data={"username": username, "password": password})
        return c
    return _make


def upload(client, name="contrat.pdf", content=b"%PDF-1.4 contrat confidentiel"):
    return client.post("/upload", data={"file": (io.BytesIO(content), name)},
                       content_type="multipart/form-data")
