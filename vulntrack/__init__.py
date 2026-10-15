import os
import secrets
from datetime import timedelta
from pathlib import Path

import click
from flask import Flask, render_template, request, session
from flask_wtf.csrf import CSRFError
from sqlalchemy import event
from sqlalchemy.engine import Engine

from .constants import CATEGORIES, SEVERITIES, STATUSES
from .extensions import csrf, db, login_manager


@event.listens_for(Engine, 'connect')
def sqlite_settings(connection, record):
    import sqlite3
    if isinstance(connection, sqlite3.Connection):
        cursor = connection.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.execute('PRAGMA busy_timeout=10000')
        cursor.close()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    secret = os.environ.get('SECRET_KEY')
    if not secret:
        secret_path = Path(app.instance_path) / '.session-secret'
        try:
            with secret_path.open('x', encoding='utf-8') as handle:
                handle.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        secret = secret_path.read_text(encoding='utf-8').strip()
    app.config.from_mapping(
        SECRET_KEY=secret,
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///vulntrack.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=256 * 1024,
        MAX_FORM_PARTS=100,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
        WTF_CSRF_TIME_LIMIT=7200,
        TRUSTED_HOSTS=os.environ.get('TRUSTED_HOSTS', 'localhost,127.0.0.1,[::1]').split(','),
        SCAN_MAX_PAGES=5,
        SCAN_MAX_SECONDS=120,
        SCAN_DELAY_SECONDS=1,
        ZAP_JAR=os.environ.get('ZAP_JAR', str(Path(app.root_path).parent / '.tools' / 'ZAP_2.17.0' / 'zap-2.17.0.jar')),
        JAVA_BIN=os.environ.get('JAVA_BIN'),
        ZAP_ENABLED=True,
        ZAP_MAX_SECONDS=120,
    )
    if test_config:
        app.config.update(test_config)
    app.json.sort_keys = False
    app.jinja_env.policies['json.dumps_kwargs'] = {'sort_keys': False}
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'web.login'
    login_manager.login_message = 'Sign in to continue.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'

    from .models import User

    @login_manager.user_loader
    def load_user(identifier):
        try:
            user_id, token = identifier.split(':', 1)
            user = db.session.get(User, int(user_id))
            if user and user.enabled and secrets.compare_digest(user.auth_token, token):
                return user
        except (ValueError, TypeError):
            return None
        return None

    from .views import web
    app.register_blueprint(web)

    @app.context_processor
    def template_globals():
        from .forms import ActionForm
        from .services.risk import priority
        from flask import url_for
        def page_url(page):
            args = request.args.to_dict()
            args['page'] = page
            return url_for(request.endpoint, **(request.view_args or {}), **args)
        return dict(STATUSES=STATUSES, CATEGORIES=CATEGORIES, SEVERITIES=SEVERITIES,
                    priority=priority, action_form=ActionForm(formdata=None), page_url=page_url)

    @app.after_request
    def secure_response(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        if request.endpoint != 'static':
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return render_template('error.html', code=400, message='Your form expired or its security token was missing. Reload the page and try again.'), 400

    for status, message in {
        400: 'The request could not be understood. Check the information and try again.',
        403: 'Your account does not have permission to access this action.',
        404: 'This record is unavailable or you do not have access to it.',
        413: 'This upload is too large. Choose a ZAP export smaller than 16 MB.',
        429: 'Too many requests. Wait a few minutes before trying again.',
        500: 'Something went wrong. Your request was not completed. Please try again.',
    }.items():
        def handler(error, code=status, text=message):
            db.session.rollback()
            return render_template('error.html', code=code, message=text), code
        app.register_error_handler(status, handler)

    @app.cli.command('init-db')
    def init_db():
        """Create the initial database. Does not overwrite existing records."""
        db.create_all()
        for index in db.metadata.tables['scan_job'].indexes:
            index.create(bind=db.engine, checkfirst=True)
        click.echo('Database initialized.')

    @app.cli.command('create-admin')
    @click.option('--email', prompt=True)
    @click.option('--name', prompt=True)
    @click.password_option(confirmation_prompt=True)
    def create_admin(email, name, password):
        """Create an administrator without placing credentials in source files."""
        from .forms import email_address
        from types import SimpleNamespace
        from wtforms.validators import ValidationError
        try:
            email_address(None, SimpleNamespace(data=email))
        except ValidationError as exc:
            raise click.ClickException(str(exc))
        if not 12 <= len(password) <= 128 or not 1 <= len(name.strip()) <= 100:
            raise click.ClickException('Use a name up to 100 characters and a password of 12–128 characters.')
        email = email.strip().lower()
        if db.session.scalar(db.select(User).where(User.email == email)):
            raise click.ClickException('That email address already exists.')
        user = User(name=name.strip(), email=email, role='admin')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo('Administrator created.')

    @app.cli.command('reset-password')
    @click.option('--email', prompt=True)
    @click.password_option(confirmation_prompt=True)
    def reset_password(email, password):
        """Operator-assisted account recovery; invalidates existing sessions."""
        from .models import AuditLog
        user = db.session.scalar(db.select(User).where(User.email == email.strip().lower()))
        if not user or not 12 <= len(password) <= 128:
            raise click.ClickException('Account not found or password outside 12–128 characters.')
        user.set_password(password)
        db.session.add(AuditLog(actor_id=user.id, action='operator_password_reset', details='Recovered through local CLI'))
        db.session.commit()
        click.echo('Password changed and existing sessions invalidated.')

    @app.cli.command('seed-demo')
    @click.option('--email', required=True, help='Existing account that will own synthetic assessments.')
    def seed_demo(email):
        from .services.demo import seed
        user = db.session.scalar(db.select(User).where(User.email == email.strip().lower()))
        if not user:
            raise click.ClickException('Create this account first.')
        if not seed(user):
            raise click.ClickException('Demo assessments already exist for this user; nothing changed.')
        click.echo('Created two synthetic assessments and 25 findings. No websites were scanned.')

    @app.cli.command('setup-demo')
    def setup_demo():
        """Initialize a local demonstration with a random administrator password."""
        from .services.demo import seed
        db.create_all()
        email = 'intern@vulntrack.local'
        if db.session.scalar(db.select(User).where(User.email == email)):
            raise click.ClickException('Demo account already exists. Use reset-password if you need account recovery.')
        password = secrets.token_urlsafe(18)
        user = User(name='Intern workspace', email=email, role='admin')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        seed(user)
        click.echo('Local demo initialized with 25 synthetic findings. No sites were scanned.')
        click.echo(f'Email: {email}')
        click.echo(f'Password (shown once): {password}')

    @app.cli.command('worker')
    @click.option('--once', is_flag=True, help='Process at most one queued job and exit.')
    def worker(once):
        """Run the durable automatic-scan queue and expire upload previews."""
        import time
        from .services.scanner import process_next
        click.echo('Automatic scan worker ready. Press Ctrl+C to stop.')
        while True:
            worked = process_next(app)
            if once:
                break
            if not worked:
                time.sleep(2)
    return app
