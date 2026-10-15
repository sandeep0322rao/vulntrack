# VulnTrack

For Railway, follow [RAILWAY.md](RAILWAY.md): it runs the web app and Java scan worker in one service with persistent storage. For a self-managed Docker host, use [DEPLOYMENT.md](DEPLOYMENT.md). The unchanged project cannot run entirely inside Vercel Functions.

VulnTrack is a Flask application for authorized vulnerability assessments. It follows the supplied internship report: ZAP JSON/XML imports, manual findings, explainable risk prioritization, OWASP Top 10 2025 suggestions, duplicate review, remediation, retests, comparison, audit events, and PDF reporting. This implementation also adds per-user ownership, administrator-managed accounts, immutable Excel/PDF report history, and automatic scans with the free ZAP engine.

## Start on Windows

Requires Python 3.11 or newer. Run from this project directory in PowerShell:

```powershell
# Install dependencies, initialize SQLite, and create an administrator interactively.
.\setup.ps1

# Start the local web server and scan worker together.
.\start.ps1
```

Open **http://127.0.0.1:5000** and sign in with the account you created. The default server binds only to your computer. If local script execution is restricted, use the direct commands below rather than changing machine policy.

For a demonstration with two assessments and 25 clearly labelled synthetic findings:

```powershell
.\setup.ps1 -Demo
```

This creates `intern@vulntrack.local` and prints a randomly generated password once. It does not scan any websites. Re-running demo setup will not reset an existing account. To add synthetic data to an existing account:

```powershell
.\.venv\Scripts\python.exe -m flask --app app seed-demo --email your-account@example.com
```

Direct setup commands:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app create-admin
.\.venv\Scripts\python.exe -m waitress --listen=127.0.0.1:5000 app:app
# In a second terminal, if you want URL checks to run:
.\.venv\Scripts\python.exe -m flask --app app worker
```

Use `reset-password --email account@example.com` through the Flask CLI for operator-assisted recovery. It prompts for a new password and invalidates all existing sessions. No email service is configured.

## Workflow

1. An administrator creates tester accounts in Team members. There is no public registration.
2. A tester creates an assessment with a customer/project, target URL, scope/exclusions, and authorization reference. Assessments belong to their creator. Administrators can review all assessments.
3. Select **Add findings** and choose exactly one intake method: **Scan a website**, **Upload a report**, or **Add manually**. All three lead to the same findings review list. Uploads accept a standard Excel template, CSV, and ZAP JSON/XML. The `samples` directory contains synthetic ZAP exports.
4. Review the affected resource, severity, evidence, confidence, suggested OWASP category, risk components, and potential duplicates. Business context defaults to 50 exploitability, 50 business impact, and 75 exposure for imported/automated findings; the assessor must review these defaults.
5. Assign remediation, update status, and record evidence. Remediated status requires an explicit retest confirmation and notes. Accepted risk and false positives require justification. Accepted risks continue contributing to open risk.
6. Create a separate retest linked to the baseline. Compare matched fingerprints and review remediated, persisting, new, and not-observed findings. Absence is never automatically proof of a fix.
7. Generate PDF or Excel from an assessment. Download it from Reports. Each report retains its data snapshot, binary content, owner context, generator, timestamp, and SHA-256. Editing findings does not change older reports.

## Roles and ownership

| Action | Tester | Administrator |
| --- | --- | --- |
| Assessments, findings, imports, remediation, comparisons, reports | Own assessments | All assessments |
| Request default automatic scan | Own approved target | Any approved target |
| Approve optional active SQLi/XSS testing | No | Yes, with separate explicit acknowledgement |
| Review target authorization and approve scans | No | Yes |
| Create or disable accounts | No | Yes |
| Global audit trail | No | Yes |
| Change own password | Yes | Yes |

Disabling an account invalidates its sessions. Existing assessments and report history are retained. Customer labels organize work; this version does not implement shared organization memberships or enterprise multi-tenancy.

Assessment deletion is available from Edit assessment and requires the exact title and your current password. It permanently removes related findings, scan history, and report snapshots, and is blocked while scans or linked retests exist. Audit events are retained without the deleted assessment link. Individual finding deletion similarly requires reauthentication and retains existing report snapshots.

## Stack and layout

- Python, Flask application factory and blueprint routes
- SQLAlchemy with SQLite, Flask-Login, Flask-WTF and WTForms
- Jinja2, vendored Bootstrap 5.3.8 and Chart.js 4.5.1
- defusedxml and Beautiful Soup for imported/observed content
- ReportLab for PDF; openpyxl for Excel
- pytest for services, workflows, and security regression checks
- Waitress for the local server

`app.py` starts the application. `vulntrack/models.py` defines persistence, `forms.py` validates input, `views.py` enforces request permissions, and `services/` contains independent intake, scoring, comparison, reporting, scanning, and demo logic. Frontend assets and templates are under `vulntrack/static/` and `vulntrack/templates/`.

The source report's architecture names SQLite; its text leaves the engine unspecified. SQLite is selected here for the internship demonstration. The source diagram's administrator/tester roles are implemented immediately to meet user-management requirements. Changes to a scan's target, authorization, or scope reset scan approval.

## Risk model

```text
score = severity × 0.40 + exploitability × 0.25
      + business impact × 0.25 + exposure × 0.10
```

Each input is 0–100. Severity presets are Critical 100, High 80, Medium 55, Low 30, and Informational 10. Priorities: Critical ≥80, High ≥60, Medium ≥40, Low <40. The finding detail page displays each weighted contribution. This project-defined score is not CVSS. OWASP mapping is heuristic, supports human overrides, and does not confirm a vulnerability.

## Guided intake and Excel uploads

The assessment workflow is **Scope → Add findings → Review issues → Track fixes → Reports**. Scan configuration, upload controls, and manual fields live on separate focused steps. Scan history, retest comparisons, and administration are collapsed in the sidebar. Optional classification/risk fields are collapsed during manual entry.

Download the standard Excel template from Upload a report. Fill the Findings worksheet with one issue per row. Title and Severity are required. Supported severity labels: Critical, High, Medium, Low, Informational. Optional fields include URL, description, evidence, remediation, method, parameter, CWE, OWASP category, and risk inputs. Blank URLs use the assessment target. Common header aliases are recognized; a workbook's Findings worksheet is preferred, otherwise the first worksheet is used.

Uploads create a private preview. Review valid rows, row-specific errors, and potential duplicates. All errors must be corrected before confirmation; partial imports are never silently accepted. Confirmation is atomic and repeat submissions do not import the same preview twice. Previews expire after 30 minutes, and the worker clears their temporary rows. Uploaded statuses are not used to bypass remediation/retest evidence requirements. Formula cells and macro-enabled contents are rejected. The Excel ZIP expansion limit is 32 MB; imports support at most 2,000 rows and 80 columns.

## Automatic scans with free ZAP

Install the official scanner in this project, then restart the app and worker:

```powershell
.\install-zap.ps1
```

Java 17+ must be on PATH, or set JAVA_BIN to its executable path. ZAP_JAR can override the default portable JAR path. The installer pins ZAP 2.17.0 and verifies its official SHA-256 before extraction. The scanner is already installed in the current local workspace under .tools, which is excluded from version control. No paid scanner account or API subscription is needed.

**Default low-impact scan:** an administrator reviews the assessment authorization and approves the public URL. The worker fetches one unauthenticated response with VulnTrack's pinned-IP client. Built-in checks and Beautiful Soup inspect headers, cookie attributes, and HTML patterns. ZAP imports the recorded response as HAR with sendRequests=false and applies its passive rules, including available information-disclosure, header, cookie, and HTML security checks. A private ZAP session starts for each job and is removed after the process exits. The loopback API requires a random per-job key. Update/telemetry requests are disabled in silent mode.

**Optional active scan:** a separate administrator acknowledgement permits active SQL injection and reflected-XSS testing. That approval expires after seven days, is tied to the exact target/scope/authorization digest, and becomes invalid if the approving administrator is disabled. The user must explicitly select active tests for each run; passive remains the default. The worker checks approval again when the job executes.

Active mode enables only ZAP rules 40012 and 40018, uses LOW attack strength and MEDIUM alert threshold, sets a one-minute scan/rule limit, one scan thread, and a 250 ms delay. It scans the selected endpoint without crawling. It works best when the target URL contains input parameters; it does not discover or submit forms or log in. ZAP runs in Protected mode with the approved endpoint in context. A loopback upstream gateway limits outgoing connections to the approved public origin and pins every connection to a freshly validated public IP. Plain HTTP forwarding also checks the exact endpoint path. HTTPS CONNECT tunnels retain origin enforcement while ZAP's context constrains the selected endpoint. Gateway connections, time, and byte transfers are bounded. Authenticated and business-logic testing remain manual work.

Network restrictions apply to both modes:

- Only HTTP/HTTPS on ports 80/443; URLs with embedded credentials are rejected.
- All resolved addresses must be public. Private, loopback, link-local, metadata, multicast, and transition destinations are blocked.
- The initial request keeps certificate verification and SNI while pinning its connection to a validated IP. Environment proxies are ignored.
- Initial redirects must stay on the same exact origin, with at most three redirects and a 1 MB response cap.
- A scan page updates status automatically and leads to the shared findings list. Failed/cancelled runs save no partial findings.
- Default request processing has a 120-second budget; socket operations use 8-second timeouts. ZAP has a separate analysis budget, and active probes have their own bounded gateway window. OS DNS resolution can exceed application timing limits, so a hosted deployment should enforce external hard timeouts.

Scanner observations require human review. No automated scan proves that a website is free of vulnerabilities. Public targets need real authorization; recorded approval documents the permission rather than replacing it. Direct Burp APIs, broad crawling, authenticated scans, and additional active policies remain outside this version.

## Security and operational limits

Passwords use Werkzeug scrypt hashing. Forms require CSRF tokens. SQLAlchemy queries bind values. Templates escape content; imports are parsed and sanitized. XML entities are rejected. Uploads are limited to 16 MB and 2,000 instances. Excel exports write untrusted values as explicit text cells, including strings starting with formula characters. Reports are stored in the database behind authenticated downloads, not under static URLs.

Login failures are limited to ten per source IP per ten minutes using persisted records. Sessions last 60 minutes, use HttpOnly/SameSite=Lax, and are invalidated on password changes or account disablement. Security headers include CSP and framing protection. All displayed record timestamps are labelled UTC.

The `instance/` directory contains the SQLite database and a generated local session secret. Keep it private and out of version control. Set a stable `SECRET_KEY` in a deployed environment. `.env.example` documents settings; `.env` is not automatically loaded. In PowerShell, set values with `$env:SECRET_KEY='your-generated-secret'`, `$env:COOKIE_SECURE='1'`, and `$env:TRUSTED_HOSTS='your-domain.example'` as appropriate. Enable secure cookies only when using HTTPS. Configure TLS, operator access, backups, and network egress controls before deployment.

This is an internship prototype, not a production security certification. SQLite is intended for local, modest datasets; report generation is synchronous and limited to 500 findings per report. Report binaries increase database size. There are no scheduled scans, email delivery, attachment storage, MFA, shared customer organizations, or external backups. Audit events are application records, not a tamper-proof external log. Initial schema creation is provided; future model changes require a reviewed migration rather than rerunning `create_all`.

Before a hosted rollout, review dependencies, perform an independent security assessment, add schema migrations, validate backup/restore, move to an appropriate production database, and isolate scan workers with external time/resource/egress limits. Keep the UI and scanner services separated when scaling.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The suite checks authentication, throttling, CSRF, ownership on reads and mutations, session invalidation, assessment lifecycle, report snapshots and Excel formula handling, ZAP imports and XML entity rejection, weighted risk boundaries, fingerprint normalization, retest comparison, SSRF destination rejection, pinned connections, redirects, and queue/cancellation/failure behavior. Default scanner tests use simulated responses and local gateway fixtures. The opt-in integration test runs the real ZAP engine against a disposable vulnerable HTTP server on loopback, verifying SQL injection and reflected-XSS detection. Its test-only origin mapping is confined to that fixture; production destination checks remain enforced. No external website is attacked by these tests.

Bootstrap and Chart.js are vendored with their licenses in `vulntrack/static/vendor/`. The internship report is retained unchanged as the implementation reference.

To run the real local scanner integration (requires ZAP and Java):

```powershell
$env:ZAP_INTEGRATION='1'
.\.venv\Scripts\python.exe -m pytest tests/test_zap_integration.py -q -s
Remove-Item Env:ZAP_INTEGRATION
```
