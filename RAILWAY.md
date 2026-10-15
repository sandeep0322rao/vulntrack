# Deploy the complete project to Railway

This setup runs the web server and scan worker in one Railway service, with the persistent SQLite database and saved report binaries on a volume mounted at /app/instance. The Dockerfile installs Java 17 and the official checksum-verified ZAP 2.17.0 release. Railway handles the public HTTPS endpoint; Caddy and Docker Compose are not used on Railway.

The service starts with Tini and deploy/railway_start.py. The launcher checks the persistent volume and secret, fixes the volume directory's ownership if Railway starts it as root, drops to UID 10001, initializes missing tables, and starts Waitress and one queue worker. If either process exits, the service exits so Railway can restart it. Keep one replica, one region, and Serverless/App Sleeping disabled so the worker can process queued jobs.

## Option A Use railway.com/new with GitHub

1. Put this source in your GitHub repository, excluding .env files, instance/, .tools/, reports, and local dependencies. Keep Dockerfile, railway.toml, deploy/railway_start.py, requirements.lock.txt, app.py, and vulntrack/ in the repository root layout supplied here.
2. Open https://railway.com/new and select GitHub Repo. Choose your repository. Railway reads the Dockerfile and railway.toml. If the initial deployment runs before configuration, it intentionally stops with a missing secret/volume message.
3. Attach a volume to this service with mount path **/app/instance**. This step is required; the launch script refuses Railway startup without it. Leave the pre-deploy command empty because Railway does not mount volumes during pre-deploy.
4. In the service Variables tab, set the following. Generate your own secret with the PowerShell command below. Do not copy a session secret from a public example.

| Variable | Value |
| --- | --- |
| SECRET_KEY | Your randomly generated 64-character hex secret |
| COOKIE_SECURE | 1 |
| DATABASE_URL | sqlite:////app/instance/vulntrack.db |
| RAILWAY_RUN_UID | 0 |
| PORT | 5000 |

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

RAILWAY_RUN_UID=0 lets startup correct the root-owned mounted directory; the launcher drops privileges before initializing the database or running application processes. Java and ZAP paths are already defined in the image. Do not add a separate ZAP service or expose its API.

5. In Settings, keep one replica, disable Serverless/App Sleeping, and allow enough memory for Python plus a Java scanner with a 512 MB heap. Start with a 2 GB service memory ceiling and observe actual usage during scans. Trial/account restrictions can constrain memory or outbound connections; check your current Railway plan before running the scanner. Hosting is usage billed, even though ZAP is free software.
6. Generate a Railway domain in Networking, target port 5000. The launcher automatically allows RAILWAY_PUBLIC_DOMAIN plus the Railway healthcheck hostname. For a custom domain, set TRUSTED_HOSTS to the exact allowed hostnames, comma separated, including **healthcheck.railway.app**. Never include https:// or a path.

If TRUSTED_HOSTS already contains the local example (localhost,127.0.0.1), replace it in Railway Variables with your actual public hostname plus healthcheck.railway.app and redeploy. An explicitly configured list takes precedence over domain discovery. For example: TRUSTED_HOSTS=your-service.up.railway.app,healthcheck.railway.app. A log entry saying the host is not trusted identifies this configuration problem. Untrusted hosts return a plain 400 response without rendering templates or echoing the supplied hostname.
7. Deploy/redeploy. The configured healthcheck is **/login**. Wait until the build and deployment are healthy, then create the first administrator using the CLI below. No public registration or automatic demo account is enabled.

## Option B Upload this local folder with the CLI

Requires Node.js/npm and a Railway account. Run from this project directory in PowerShell. These commands create Railway resources and deploy the app when you run them; review the linked project/service before proceeding.

```powershell
npm install -g @railway/cli
railway login
railway init --name vulntrack
railway add --service vulntrack
railway volume add --mount-path /app/instance
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))" | railway variable set SECRET_KEY --stdin --skip-deploys
railway variable set COOKIE_SECURE=1 RAILWAY_RUN_UID=0 PORT=5000 DATABASE_URL=sqlite:////app/instance/vulntrack.db --skip-deploys
railway domain --port 5000
railway up
```

For an existing project created at railway.com/new, replace init/add with **railway link** and select its existing service. Do not create a second service or volume by repeating setup commands on an existing deployment. Configure one replica, disabled sleeping, and appropriate resource limits in its dashboard before expecting background scans to run reliably.

## Create the first administrator

Open an interactive shell inside the running Railway container:

```powershell
railway ssh
```

Then run inside that remote shell:

```bash
gosu vulntrack python -m flask --app app create-admin
exit
```

The command prompts for name, email, and a 12-128 character password. Sign in at the Railway HTTPS URL and create tester accounts in Team members. Use **railway ssh**, rather than **railway run**, for this step: railway run executes on your own computer and cannot access the Railway-mounted SQLite file. If the SSH shell already runs as UID 10001, omit gosu and run python directly. First-time SSH may prompt to register your SSH key.

## Verify the hosted app

- Sign in, create an assessment, add a manual finding, and confirm it appears only for its owner/admin.
- Download the Excel template, upload a filled workbook, inspect the preview, and confirm it once.
- Generate PDF and Excel reports, restart/redeploy, and confirm records and old report downloads remain available. Do this persistence check before using important data.
- Approve an authorized public target, run a default scan, and check progress in both the UI and service logs. Optional active tests require the separate administrator approval and per-run opt-in. No target is scanned automatically during deployment.
- Inspect **railway logs**, resource usage, and volume usage. Configure Railway volume backups and test restore into a separate environment. Stored report binaries grow the database.

The deployment begins with an empty database. Existing Windows users, synthetic data, touchpoint assessments, and reports remain local unless deliberately migrated. Do not upload a live SQLite file while it is being written; use a consistent backup for any later migration.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Missing volume or permission error | Check mount path /app/instance and RAILWAY_RUN_UID=0; redeploy. |
| HTTP 400 or failed healthcheck | Check PORT=5000 and exact TRUSTED_HOSTS if set; include healthcheck.railway.app. |
| Login repeats after redeploy | Preserve SECRET_KEY and ensure the browser uses HTTPS with COOKIE_SECURE=1. |
| Scan remains queued | Check worker startup logs and disable sleeping; keep one running replica. |
| Java killed or scan fails during analysis | Inspect memory/OOM events; adjust the service resource ceiling and plan. |
| Outbound scan connections fail | Check Railway account/network restrictions and target authorization; the app still rejects private/internal targets. |

The application regression suite passes locally. The Railway configuration is prepared against the official documentation, but no Railway account, resource creation, public deployment, certificate, container build, or hosted scan has been verified in this workspace.

Official references checked on 15 October 2026: https://docs.railway.com/volumes, https://docs.railway.com/deployments/healthchecks, https://docs.railway.com/config-as-code/reference, https://docs.railway.com/cli/up, https://docs.railway.com/cli/variable, https://docs.railway.com/cli/ssh, https://docs.railway.com/pricing/free-trial.
