import pytest

from vulntrack import create_app
from vulntrack.extensions import db
from vulntrack.models import Assessment, User


@pytest.fixture
def app(tmp_path):
    app = create_app({'TESTING': True, 'SECRET_KEY': 'test-only-secret', 'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + (tmp_path / 'test.db').as_posix(), 'WTF_CSRF_ENABLED': False, 'ZAP_ENABLED': False})
    # The fixture retains an app context for ORM assertions; clear the cached
    # request user so independent browser clients still reload their sessions.
    @app.teardown_request
    def clear_request_user(error=None):
        from flask import g
        g.pop('_login_user', None)
        g.pop('csrf_token', None)
        g.pop('csrf_valid', None)
    with app.app_context():
        db.create_all()
        for name, role in [('Alice', 'tester'), ('Bob', 'tester'), ('Admin', 'admin')]:
            user = User(name=name, email=f'{name.lower()}@example.com', role=role)
            user.set_password('TestPassword-Only123!')
            db.session.add(user)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def signed_in(client):
    result = client.post('/login', data={'email': 'alice@example.com', 'password': 'TestPassword-Only123!'})
    assert result.status_code == 302
    return client


@pytest.fixture
def assessment(app):
    a = Assessment(owner_id=1, title='Authorized portal baseline', client='Example lab', target_url='https://portal.example.com/',
                   scope='Authorized lab assessment, excluding payment and logout endpoints.', authorization_ref='LAB-2026-001')
    db.session.add(a)
    db.session.commit()
    return a
