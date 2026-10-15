"""Run one web process and one worker with the same persistent SQLite volume."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def configure_environment():
    instance = Path('/app/instance')
    if os.environ.get('RAILWAY_ENVIRONMENT_ID'):
        if os.environ.get('RAILWAY_VOLUME_MOUNT_PATH') != str(instance):
            raise RuntimeError('Attach a Railway volume at /app/instance before deploying.')
    if len(os.environ.get('SECRET_KEY', '')) < 32:
        raise RuntimeError('Set a stable, randomly generated SECRET_KEY of at least 32 characters.')
    port = int(os.environ.get('PORT', '5000'))
    if not 1024 <= port <= 65535:
        raise RuntimeError('PORT must be between 1024 and 65535.')
    os.environ.setdefault('DATABASE_URL', 'sqlite:////app/instance/vulntrack.db')
    os.environ.setdefault('COOKIE_SECURE', '1')
    if not os.environ.get('TRUSTED_HOSTS'):
        hosts = ['healthcheck.railway.app', 'localhost', '127.0.0.1']
        if os.environ.get('RAILWAY_PUBLIC_DOMAIN'):
            hosts.insert(0, os.environ['RAILWAY_PUBLIC_DOMAIN'])
        os.environ['TRUSTED_HOSTS'] = ','.join(hosts)
    instance.mkdir(parents=True, exist_ok=True)
    # Railway volumes mount as root. Change only the app directory and its DB
    # files before dropping privileges; never run the web or scanner as root.
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        os.chown(instance, 10001, 10001)
        for name in ('vulntrack.db', 'vulntrack.db-journal', 'vulntrack.db-wal', 'vulntrack.db-shm'):
            path = instance / name
            if path.is_file() and not path.is_symlink():
                os.chown(path, 10001, 10001)
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    return port


def main():
    port = configure_environment()
    subprocess.run([sys.executable, '-m', 'flask', '--app', 'app', 'init-db'], check=True)
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
             '--trusted-proxy-headers=x-forwarded-for x-forwarded-proto', 'app:app'],
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
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 15
        for child in children:
            try:
                child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


if __name__ == '__main__':
    sys.exit(main())
