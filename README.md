# Vysion — FortiGate configuration audit

Reads a FortiGate `.conf` backup, runs 57 compliance checks against it, and
produces Excel and Word audit reports in French.

Internal tool for SNS Security.

## Run it

```bash
cp .env.example .env          # optional, defaults are fine
docker compose up -d --build
```

Then open <http://localhost:8000>. One container serves both the UI and the API.

Reports are written to the `vysion-reports` volume. **They are client
deliverables — back that volume up, and do not expose this service outside the
internal network.** There is no authentication: anyone who can reach the URL can
run audits and download every report that has ever been generated.

### Network access

The firmware CVE check calls `fortiguard.com`. Allow outbound HTTPS to it if you
can. Without it the check reports that verification was not possible, rather
than passing silently — see *Known issues* below.

## Using it

1. Upload a FortiGate `.conf` file
2. Fill in client, site, serial number, licence dates
3. Select which interfaces and zones count as WAN
4. Set the audit options (UTM licence, MPLS/L2L, HA cabling, rules with no match)
5. Run the audit, then download the Excel and Word reports

## Developing

Nothing here requires Docker. Running the two servers on your machine works as
it always has:

```powershell
cd modern_audit_app\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

```powershell
cd modern_audit_app\frontend
npm install
npm run dev          # http://localhost:5173, proxies /api to port 8000
```

`start.bat` does both in one step on Windows.

If you want the containers instead — same code, but matching what gets
deployed — use:

```bash
docker compose -f docker-compose.dev.yml up
```

That bind-mounts the source, so editing in PyCharm reloads the running
container with no rebuild. Backend on 8000, frontend on 5173.

## Layout

```
modern_audit_app/
  backend/
    app/
      main.py                  FastAPI app: 4 endpoints, serves the built UI
      audit/
        services.py            runs every check, collects results
        reports.py             hands results to the Excel/Word generators
        legacy_functions.py    the audit engine — 12k lines, 57 checks
        models.py              request models
    Références/                logos, templates, the model EOL workbook
  frontend/src/App.tsx         the whole UI: a six-step wizard
legacy/                        the original Tkinter app, archived, not deployed
```

`legacy_functions.py` is the file the running application uses. `legacy/` is
reference only — see `legacy/README.md`.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/upload` | Parse a config, return hostname, version, model, interfaces, zones |
| `POST /api/audit` | Run all checks, generate both reports, return results and download links |
| `GET /api/download/{filename}` | Fetch a generated report |
| `GET /health` | Liveness check |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VYSION_PORT` | `8000` | Host port to publish |
| `CORS_ORIGINS` | Vite dev server | Comma-separated allowed origins. Not needed in the single-container setup, where UI and API share an origin |
| `REPORTS_DIR` | `reports` | Where reports are written. Set to the volume path in the image |
| `FRONTEND_DIR` | `static` | Compiled UI. If absent, the app serves the API only |

## Known issues

**The CVE check cannot currently reach its data source.** `fortiguard.com` is
behind bot protection that answers with HTTP 200 and a "verifying connection
security" page instead of the advisory listing. The check now detects this and
reports *vérification impossible*, flagging the finding for manual review. It
previously reported those runs as "no CVEs found", so **the CVE section of
reports produced before this was fixed cannot be relied on**. The durable fix is
to move to Fortinet's PSIRT API instead of scraping HTML.

**There are no automated tests.** Any change to `legacy_functions.py` is
verified by running an audit and reading the output. A fixture config and a few
tests around the parsing functions would be the highest-value thing to add next.

**There is no authentication.** See the warning above.

## What not to commit

`.gitignore` already covers these, but to be explicit: generated reports,
FortiGate `.conf` files, `token_cache.bin`, virtualenvs, and the compiled
`.exe` builds. Reports and configs both contain real client data.
