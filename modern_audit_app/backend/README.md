## Backend (FastAPI)

### Setup
```powershell
cd backend
python -m venv .venv
. .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Testing
```powershell
pytest
```

### Notes
- The legacy audit logic is loaded from `../.venv/main_audit.py` via `LegacyAdapter`. Update `AUDIT_LEGACY_PATH` env var if you relocate it.
- `/audit` expects a FortiGate `.conf` file and optional JSON options in the `options` form field.







