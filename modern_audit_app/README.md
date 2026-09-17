# Modern FortiGate Audit Application

A complete rewrite of the FortiGate configuration audit tool with a modern web-based interface. This application performs comprehensive security audits of FortiGate firewall configurations and generates detailed Excel and Word reports.

## Features

- **Complete Audit Coverage**: All 67+ audit checks from the original application
- **Modern Web UI**: React-based interface with multi-step workflow
- **Interface Selection**: Interactive selection of WAN interfaces and zones
- **Excel Reports**: Comprehensive Excel reports with multiple sheets
- **Word Reports**: Detailed Word documents with risk analysis tables
- **Real-time Progress**: Progress tracking during audit execution

## Architecture

- **Backend**: FastAPI (Python) - RESTful API for audit processing
- **Frontend**: React + Vite + TypeScript - Modern single-page application
- **Legacy Integration**: Seamlessly integrates with existing audit functions

## Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn
- Access to the legacy audit script at `../.venv/main_audit.py`

## Quick Start

### Easy Launch (Recommended)

Simply run the launcher script to start both backend and frontend:

```batch
cd modern_audit_app
start.bat
```

This will:
- Check prerequisites (Python, Node.js)
- Set up virtual environments if needed
- Install dependencies automatically
- Start both servers in minimized windows
- Open the application in your browser

### Manual Setup

If you prefer to start servers manually:

#### Backend Setup

1. Navigate to the backend directory:
   ```powershell
   cd modern_audit_app\backend
   ```

2. Create and activate virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Start the server:
   ```powershell
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

#### Frontend Setup

1. Navigate to the frontend directory:
   ```powershell
   cd modern_audit_app\frontend
   ```

2. Install dependencies:
   ```powershell
   npm install
   ```

3. Start the development server:
   ```powershell
   npm run dev
   ```

4. Open your browser to `http://localhost:5173`

## Usage

1. **Upload Configuration**: Select your FortiGate `.conf` file
2. **Select WAN Interfaces**: Choose which interfaces/zones should be considered WAN
3. **Configure Options**: Set UTM license status and MPLS L2L presence
4. **Run Audit**: Execute the audit (takes 30-90 seconds depending on config size)
5. **Download Reports**: Get Excel and Word reports with detailed findings

## API Endpoints

### `POST /api/upload`
Upload a FortiGate configuration file and get interface/zone information.

**Request**: Multipart form with `file` field
**Response**: JSON with hostname, version, model, interfaces, zones, and SD-WAN zones

### `POST /api/audit`
Run the complete audit with specified options.

**Request**: Multipart form with:
- `file`: Configuration file
- `utm_license`: Boolean (default: true)
- `mpls_l2l`: Boolean (default: false)
- `wan_interfaces`: JSON array of selected WAN interface names

**Response**: JSON with audit results and download links for reports

### `GET /api/download/{filename}`
Download a generated report file (Excel or Word).

## Project Structure

```
modern_audit_app/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Configuration settings
│   │   └── audit/
│   │       ├── services.py      # Audit orchestration
│   │       ├── reports.py       # Report generation
│   │       ├── legacy_adapter.py # Legacy code integration
│   │       └── models.py        # Pydantic models
│   ├── tests/                   # Test suite
│   └── requirements.txt         # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.tsx              # Main React component
│   │   ├── App.css              # Styles
│   │   ├── main.tsx             # Entry point
│   │   └── types.ts             # TypeScript types
│   ├── package.json             # Node dependencies
│   └── vite.config.ts           # Vite configuration
├── start.bat                    # Single launcher script for both servers
└── README.md                    # This file
```

## Audit Checks Performed

The application performs comprehensive checks across multiple categories:

### System
- Firmware version and CVE vulnerabilities
- Model EOL status
- Automatic backups
- Unused objects
- USB auto-installation

### Administration & Accounts
- Guest accounts
- Admin accounts
- HTTPS admin port
- FortiManager/FortiAnalyzer sync
- MFA for admin users
- LDAPS configuration
- Admin access via loopback

### Network & Traffic
- VIP/VS with external interface "any"
- SSL VPN usage
- All ports in rules
- Geo-IP usage
- ISDB presence
- HTTP/HTTPS on WAN interfaces
- CTI threat intelligence
- Port deny rules
- SD-WAN usage

### High Availability
- Session pickup
- Interface redundancy
- HA override

### VPN
- IKE version
- Diffie-Hellman groups
- Encryption algorithms
- IPsec split tunneling

### Security Profiles
- Security profiles on rules
- Mail filter
- Web filter
- Antivirus
- DNS filter
- IPS
- App Control
- SSL/SSH inspection

### WiFi/FortiAP
- Obsolete FortiAP models
- SSID count per profile
- 5GHz band usage
- DARRP
- Frequency handoff
- TIM
- Band/channel compliance
- Short guard interval

## Configuration

The backend looks for the legacy audit script at `../.venv/main_audit.py` by default. You can override this by setting the `AUDIT_LEGACY_PATH` environment variable.

## Development

### Backend Development

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

### Frontend Development

```powershell
cd frontend
npm run dev
```

### Running Tests

```powershell
cd backend
pytest
```

## Troubleshooting

### Legacy Script Not Found
Ensure the legacy audit script exists at `../.venv/main_audit.py` relative to the backend directory, or set `AUDIT_LEGACY_PATH` environment variable.

### Port Already in Use
Change the port in `uvicorn` command or frontend `vite.config.ts`.

### Missing Dependencies
Run `pip install -r requirements.txt` (backend) or `npm install` (frontend).

## License

Internal tool for SNS Security.

## Notes

- The application maintains full feature parity with the original Tkinter application
- All audit checks are executed in the same order as the legacy code
- Reports are generated using the original Excel/Word generation functions
- The UI provides a modern, intuitive interface while preserving all functionality
