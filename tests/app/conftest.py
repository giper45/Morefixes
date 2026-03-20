import base64

import pytest

from app import create_app
from app.extensions import db


@pytest.fixture()
def app_instance(tmp_path):
    database_path = tmp_path / "app-test.sqlite"
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "AUTH_USER": "swadmin",
            "AUTH_PASSWORD": "test-secret",
        }
    )

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app_instance):
    return app_instance.test_client()


@pytest.fixture()
def auth_headers():
    token = base64.b64encode(b"swadmin:test-secret").decode("ascii")
    return {"Authorization": f"Basic {token}"}
