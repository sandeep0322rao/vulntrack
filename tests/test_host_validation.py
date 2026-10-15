from vulntrack import create_app


def test_untrusted_host_returns_400_without_rendering_templates(app, monkeypatch):
    def unexpected_render(*args, **kwargs):
        raise AssertionError('An untrusted host must not reach template URL generation.')

    monkeypatch.setattr('vulntrack.render_template', unexpected_render)
    client = app.test_client()
    for path in ('/', '/login', '/favicon.ico'):
        response = client.get(path, base_url='https://untrusted.example')
        assert response.status_code == 400
        assert response.mimetype == 'text/plain'
        assert b'untrusted.example' not in response.data
        assert response.headers['Cache-Control'] == 'no-store'


def test_configured_deployment_and_healthcheck_hosts_are_accepted(monkeypatch):
    monkeypatch.setenv('SECRET_KEY', 'test-only-host-validation-secret-' * 2)
    monkeypatch.setenv('TRUSTED_HOSTS',
                       'vulntrack-production-e451.up.railway.app, healthcheck.railway.app, localhost, ')
    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'})
    client = app.test_client()
    for host in ('vulntrack-production-e451.up.railway.app', 'healthcheck.railway.app', 'localhost'):
        assert client.get('/login', base_url=f'https://{host}').status_code == 200
    assert client.get('/not-a-route', base_url='https://vulntrack-production-e451.up.railway.app').status_code == 404
    assert client.get('/login', base_url='https://another-service.up.railway.app').status_code == 400
