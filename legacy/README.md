# Legacy application (archive — not deployed)

The original Tkinter desktop application, kept for reference. **Nothing here runs in
the Docker image**, and the web app does not import from this directory.

| File | What it is |
|---|---|
| `main_audit.py` | The original desktop app (Tkinter GUI + audit engine + report generators), 2025-11-27 |
| `main_audit_snapshot_2025-10-24.py` | An earlier snapshot of the same file, previously named `2025-10-24 - Code Audit.txt` |
| `main_audit.spec` | PyInstaller spec used to build `VYSION.exe` |

These files were recovered from the `.venv/` directory, where they had been saved
alongside a real Python virtualenv. `.venv/` is excluded from the repository; these
copies are the tracked versions.

## Relationship to the web app

`modern_audit_app/backend/app/audit/legacy_functions.py` is a copy of the audit
engine from `main_audit.py` with the GUI imports removed. The two have since
drifted. When changing audit logic, change `legacy_functions.py` — that is the
file the running application uses.

The compiled `VYSION.exe` / `VYSION-1.0.exe` binaries (49 MB each) are not tracked.
