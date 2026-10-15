# Run the complete VulnTrack project

The supported single-host layout runs Flask/Waitress and the Java ZAP scan worker as separate containers. Both use a persistent SQLite volume. Caddy can provide the public HTTPS endpoint. This preserves the internship stack and includes all three finding intake methods, background scans, user accounts, and saved Excel/PDF reports.

Vercel can host a Flask request handler, but this project also needs a persistent database and a long-running Java worker. Its current local filesystem layout, static assets, scanner installation, and worker are not a complete Vercel deployment. A Vercel version would require a separate hosted database and worker, filesystem/static-asset adaptation, and deployment testing. Do not use a temporary SQLite file on Vercel for user data. The commands below deploy the complete app together, as selected.

## Requirements

- Docker Engine with Compose v2 on a Linux server, or Docker Desktop running Linux containers for local verification.
- Network access during the build for the Python base image, Debian packages, pinned Python dependencies, and the official ZAP archive. ZAP 2.17.0 is checksum verified.
- Capacity for the configured container memory limits: web 768 MB and worker 1.5 GB, plus operating-system and Docker overhead. The worker starts a Java process for a job.
- For public hosting: a domain pointing to the server and incoming TCP ports 80/443 available. This Compose layout is a single-server internship deployment; do not scale SQLite replicas across servers.

## Windows PowerShell local container preview

Run from the project folder. These containers use a new database volume and do not modify the database used by the currently running Windows app.

```powershell
Copy-Item .env.docker.example .env.docker
$taskSecret = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
(Get-Content .env.docker) -replace '^SECRET_KEY=.*', "SECRET_KEY=$taskSecret" | Set-Content .env.docker
docker compose --env-file .env.docker config --quiet
docker compose --env-file .env.docker build
docker compose --env-file .env.docker run --rm init-db
docker compose --env-file .env.docker run --rm web python -m flask --app app create-admin
docker compose --env-file .env.docker up -d web worker
docker compose --env-file .env.docker ps
```

Open http://127.0.0.1:8000 and use the administrator account you just created. Keep .env.docker private. Only copy the example if .env.docker does not already exist; preserve an existing secret and settings when upgrading.

## Linux server deployment with HTTPS

Copy the project source to the server, enter its folder, and run the following. Use your actual hostname in place of vulntrack.example.com. Docker and the Compose plugin must already be installed. These commands create a fresh database; local demonstration records are not copied automatically.

```bash
cp .env.docker.example .env.docker
chmod 600 .env.docker
docker run --rm python:3.11-slim-bookworm python -c 'import secrets; print("SECRET_KEY=" + secrets.token_hex(32))' > .env.docker
printf '%s\n' 'DOMAIN=vulntrack.example.com' >> .env.docker

docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml config --quiet
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml build
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml run --rm init-db
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml run --rm web python -m flask --app app create-admin
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml up -d web worker caddy
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml ps
```

Caddy obtains and renews the domain's HTTPS certificate when DNS and external ports are correct. The HTTPS override enables Secure cookies and restricts allowed web hosts to DOMAIN. Waitress trusts one proxy hop on the private container network for the client address and HTTPS scheme. The app port is published only to the server's loopback address; ZAP APIs and the worker have no published ports. Keep the web service behind the included proxy.

Visit https://your-hostname, create tester accounts, create an assessment, and use Add findings. An administrator must approve target authorization before scans; active SQLi/XSS testing needs a separate explicit approval. The scanner still blocks private/loopback targets even when deployed in containers.

## Operations

Use the same --env-file and -f arguments used at startup for every command. Examples for the HTTPS deployment:

```bash
# Read recent logs; Ctrl+C stops following logs, not the app.
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml logs --tail=100 -f web worker caddy

# Reset a password interactively; existing sessions for that user are invalidated.
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml run --rm web python -m flask --app app reset-password --email you@example.com

# Stop services while retaining database and certificate volumes.
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml down
```

Do not append --volumes to down unless intentionally deleting stored assessments, users, reports, and certificates. Keep one worker for this SQLite deployment. Store off-server backups, review updates before rebuilding, and plan a reviewed schema migration before changing models. Restarted scan jobs may be marked failed by the queue's stale-job recovery; users can review and retry them.

## Backup and restore

The database includes credentials as password hashes, assessment data, import previews, audit entries, and saved report binaries. Back up the data volume as sensitive information. Pause writes and the worker before copying SQLite. On Linux, from the project directory:

```bash
mkdir -p backups
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml stop web worker
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml run --rm --no-deps -v "$PWD/backups:/backup" web python -c 'import shutil; from datetime import datetime, timezone; shutil.copy2("/app/instance/vulntrack.db", "/backup/vulntrack-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".db")'
docker compose --env-file .env.docker -f compose.yaml -f compose.https.yaml up -d web worker
```

The app runs as UID 10001. Make the backup directory writable by that UID before the copy (for example, sudo chown 10001:10001 backups on the Linux server). Record the backup filename and copy it to protected off-server storage. Keep the session secret separately in your secret manager. Test restoration into a separate deployment before relying on backups; restoration replaces that deployment's database and must happen while its writers are stopped.

## Validation status

Compose configuration can be validated without publishing anything. A successful config check does not prove an image builds or the service works on a host. See the updated implementation report for the application regression results and the separately exercised real-ZAP local integration. Public hosting, certificate issuance, and container build/start must be verified on the destination Docker host.

Official deployment references checked on 15 October 2026:

- https://vercel.com/docs/frameworks/backend/flask
- https://vercel.com/docs/functions/runtimes
- https://docs.docker.com/compose/how-tos/production/
- https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/
- https://caddyserver.com/docs/quick-starts/https
