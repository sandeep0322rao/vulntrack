"""Run one web process and one worker with the same persistent SQLite volume."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def configure_environment():
    instance = Path('/app/instance')
    if os.environ.get('RAILWAY_ENVIRONMENT_ID') and os.environ.get('ALLOW_EPHEMERAL') != '1':
        mount_path = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH')
        normalized_mount = Path(mount_path).as_posix() if mount_path else None
        if normalized_mount != instance.as_posix():
            raise RuntimeError(
                'Attach a Railway volume at /app/instance before deploying, '
                'or set ALLOW_EPHEMERAL=1 in Railway Variables to run with temporary container storage.'
            )
    elif os.environ.get('ALLOW_EPHEMERAL') == '1':
        print(
            'Notice: ALLOW_EPHEMERAL=1 is active. Running with container-local storage '
            '(data will reset on restart/redeploy). To persist database and reports, attach a Railway '
            'volume at /app/instance.',
            flush=True
        )

    secret_key = os.environ.get('SECRET_KEY', '').strip()
    if len(secret_key) < 32:
        if os.environ.get('AUTO_GENERATE_SECRET') == '1' or os.environ.get('ALLOW_EPHEMERAL') == '1':
            secret_file = instance / '.session-secret'
            if secret_file.is_file():
                try:
                    secret_key = secret_file.read_text(encoding='utf-8').strip()
                except OSError:
                    secret_key = ''
            if len(secret_key) < 32:
                import secrets
                secret_key = secrets.token_hex(32)
                try:
                    instance.mkdir(parents=True, exist_ok=True)
                    secret_file.write_text(secret_key, encoding='utf-8')
                except OSError:
                    pass
            os.environ['SECRET_KEY'] = secret_key
            print(
                'Notice: SECRET_KEY auto-generated and saved in .session-secret. '
                'For production, set SECRET_KEY in Railway Variables.',
                flush=True
            )
        else:
            raise RuntimeError(
                'Set a stable, randomly generated SECRET_KEY of at least 32 characters in Railway Variables, '
                'or set AUTO_GENERATE_SECRET=1.'
            )

    port = int(os.environ.get('PORT', '5000'))
    if not 1024 <= port <= 65535 and port != 80:
        raise RuntimeError('PORT must be between 1024 and 65535 (or 80).')
    os.environ.setdefault('DATABASE_URL', 'sqlite:////app/instance/vulntrack.db')
    os.environ.setdefault('COOKIE_SECURE', '1')
    hosts = [h.strip() for h in os.environ.get('TRUSTED_HOSTS', '').split(',') if h.strip()]
    for default_host in (
        'healthcheck.railway.app',
        '.railway.app',
        '.up.railway.app',
        'localhost',
        '127.0.0.1',
        '[::1]',
    ):
        if default_host not in hosts:
            hosts.append(default_host)
    for env_domain in ('RAILWAY_PUBLIC_DOMAIN', 'RAILWAY_STATIC_URL', 'RAILWAY_TCP_PROXY_DOMAIN'):
        val = os.environ.get(env_domain)
        if val and val.strip() and val.strip() not in hosts:
            hosts.insert(0, val.strip())
    os.environ['TRUSTED_HOSTS'] = ','.join(dict.fromkeys(hosts))

    instance.mkdir(parents=True, exist_ok=True)
    # Railway volumes mount as root. Change only the app directory and its DB
    # files before dropping privileges; never run the web or scanner as root.
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        os.chown(instance, 10001, 10001)
        for name in ('vulntrack.db', 'vulntrack.db-journal', 'vulntrack.db-wal', 'vulntrack.db-shm', '.session-secret'):
            path = instance / name
            if path.is_file() and not path.is_symlink():
                try:
                    os.chown(path, 10001, 10001)
                except OSError:
                    pass
        if hasattr(os, 'setgroups'):
            os.setgroups([])
        if hasattr(os, 'setgid'):
            os.setgid(10001)
        if hasattr(os, 'setuid'):
            os.setuid(10001)
    return port


def main():
    port = configure_environment()
    subprocess.run([sys.executable, '-m', 'flask', '--app', 'app', 'init-db'], check=True)
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@vulntrack.com').strip().lower()
    admin_password = os.environ.get('ADMIN_PASSWORD', '123456')
    admin_name = os.environ.get('ADMIN_NAME', 'admin')
    if admin_email and len(admin_password) >= 6:
        try:
            res = subprocess.run([
                sys.executable, '-m', 'flask', '--app', 'app', 'create-admin',
                '--email', admin_email,
                '--name', admin_name,
                '--password', admin_password,
            ], capture_output=True, text=True)
            if res.returncode == 0:
                print(f'Administrator created: {admin_name} / {admin_email} (password: {admin_password})', flush=True)
            else:
                subprocess.run([
                    sys.executable, '-m', 'flask', '--app', 'app', 'reset-password',
                    '--email', admin_email,
                    '--password', admin_password,
                ], capture_output=True, text=True)
                print(f'Administrator password synchronized for {admin_email}', flush=True)
        except Exception:
            pass
    children = []
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        commands = [
            [sys.executable, '-m', 'flask', '--app', 'app', 'worker'],
            [sys.executable, '-m', 'waitress', f'--listen=0.0.0.0:{port}', '--threads=4',
             '--trusted-proxy=*', '--trusted-proxy-count=1',
             '--trusted-proxy-headers=x-forwarded-for x-forwarded-proto x-forwarded-host x-forwarded-port', 'app:app'],
        ]
        for command in commands:
            children.append(subprocess.Popen(command, start_new_session=True))
        print(f'Web and scan worker started on port {port}; persistent database is ready.', flush=True)
        while not stopping:
            for child in children:
                if child.poll() is not None:
                    print(f'Child process exited ({child.returncode}); restarting the service is required.', flush=True)
                    return 1
            time.sleep(0.5)
        return 0
    finally:
        # Include Java descendants in shutdown. Tini reaps orphaned processes.
        for child in children:
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(child.pid, signal.SIGTERM)
                else:
                    child.terminate()
            except (ProcessLookupError, OSError):
                pass
        deadline = time.monotonic() + 15
        for child in children:
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        for child in children:
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
            except (ProcessLookupError, OSError):
                pass


if __name__ == '__main__':
    sys.exit(main())
