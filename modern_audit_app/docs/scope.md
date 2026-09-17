## Project Scope

### Overview
- Main application lives at `.venv/main_audit.py` (Tkinter GUI).
- Purpose: audit FortiGate configuration backups and generate compliance reports.
- Author credit present in code header: Thierry HOKMAYAN for SNS Security.

### How It Works
- User imports a FortiGate `.conf` file, selects WAN interfaces/zones, and sets options (UTM licence, MPLS flag).
- The app parses the configuration (interfaces, zones, VPN, firewall objects/rules, profiles, Wi‑Fi, HA, logging, certificates, admin accounts).
- Runs many conformity checks (guest/admin accounts, VIP/VS any, implicit deny logging, SSL VPN usage, LDAP/LDAPS, backups, HTTPS admin port, IPS/AV/webfilter/app-control profiles, CTI/ISDB presence, geo-IP, SD-WAN, HA settings, DNS/FortiGuard/FortiSandbox updates, EOL/CVE for model/version, Wi‑Fi/FortiAP settings, etc.).
- Produces Excel and Word audit reports with risk tables, summaries, and charts; uses cache and optional Azure login (MSAL) helpers.

### Key Dependencies (from code imports)
- GUI/reporting: `tkinter`, `Pillow`, `openpyxl`, `python-docx`, `pandas`.
- Networking/HTML: `requests`, `beautifulsoup4`.
- Auth/cache: `msal`, `pickle`.
- Standard libs: `datetime`, `threading`, `shutil`, `os`, `sys`, `re`.

### Inputs / Outputs
- Input: FortiGate configuration file (.conf) provided via file picker; optional Azure credentials for login flow.
- Output: Excel workbook and Word document summarizing compliance results and non-conformities; on-screen Tkinter status/progress.

### Next Steps
- Document expected config file format and required FortiGate versions/models.
- Add run instructions (Python version, how to launch `main_audit.py` from `.venv`, required packages).
- Provide sample config and example generated reports for validation.
- Add automated tests or fixtures for key parsing and conformity checks.

