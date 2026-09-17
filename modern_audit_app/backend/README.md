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
- The audit logic lives in `app/audit/legacy_functions.py` in this project. It is
  no longer loaded from an external file, and `AUDIT_LEGACY_PATH` is not read.
- `/api/audit` expects a FortiGate `.conf` file plus the audit options as
  individual multipart form fields (see `app/main.py`).







