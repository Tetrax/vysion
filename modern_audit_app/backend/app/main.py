"""
FastAPI application for FortiGate audit.
"""
import logging
import traceback
import os
from pathlib import Path
from tempfile import mkdtemp
from typing import Dict, Any, List

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from app.audit.models import AuditOptions
from app.audit.services import run_complete_audit
from app.audit.reports import generate_excel_report, generate_word_report
from app.audit import legacy_functions

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Modern FortiGate Audit API", version="1.0.0")

# CORS. Origins are configured via the CORS_ORIGINS env var (comma separated).
# In the Docker image the frontend is served by this same app, so requests are
# same-origin and no entry is needed; the defaults cover the Vite dev server.
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Create reports directory
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/upload")
async def upload_config(file: UploadFile = File(...)):
    """
    Upload config file and return interfaces/zones for selection.
    """
    if not file.filename or not file.filename.lower().endswith(".conf"):
        raise HTTPException(status_code=400, detail="Expected a FortiGate .conf file")

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="File is empty")

    try:
        # Write to temp file
        from tempfile import NamedTemporaryFile
        tmp = NamedTemporaryFile(delete=False, suffix=".conf")
        tmp.write(contents)
        tmp.flush()
        tmp.close()  # Close the file handle before using the file
        tmp_path = Path(tmp.name)

        try:
            # Read interfaces and zones
            active_interfaces = legacy_functions.read_active_interfaces(str(tmp_path))
            zones, sdwan_zones = legacy_functions.read_zones(str(tmp_path), active_interfaces)

            # Extract hostname
            config_lines = legacy_functions.lire_config_fortigate(str(tmp_path))
            hostname = legacy_functions.extraire_hostname(config_lines)
            version_info, version, model = legacy_functions.extraire_modele_version_fortigate(config_lines)

            return {
                "hostname": hostname,
                "version": version,
                "model": model,
                "interfaces": [
                    {
                        "name": name,
                        "alias": data.get("alias", ""),
                        "role": data.get("role"),
                        "active": data.get("active", True),
                    }
                    for name, data in active_interfaces.items()
                ],
                "zones": [
                    {
                        "name": name,
                        "interfaces": data.get("interfaces", []),
                        "is_wan_zone": data.get("is_wan_zone", False),
                    }
                    for name, data in zones.items()
                ],
                "sdwan_zones": [
                    {
                        "name": name,
                        "interfaces": data.get("interfaces", []),
                        "is_wan_zone": data.get("is_wan_zone", False),
                    }
                    for name, data in sdwan_zones.items()
                ],
            }
        finally:
            # Ensure file is closed before deletion on Windows
            try:
                tmp_path.unlink(missing_ok=True)
            except PermissionError:
                # File might still be in use, ignore
                pass

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error processing config: {str(exc)}") from exc


@app.post("/api/audit")
async def run_audit_endpoint(
    file: UploadFile = File(...),
    utm_license: bool = Form(False),
    mpls_l2l: bool = Form(False),
    ha_cabling_redundancy: bool = Form(False),
    regle_no_match: int = Form(0),
    wan_interfaces: str = Form(""),
    client_name: str = Form(""),
    site_name: str = Form(""),
    serial_number: str = Form(""),
    license_end_date: str = Form(""),
    system_uptime: str = Form(""),
):
    """
    Run complete audit and generate reports.
    """
    logger.info("=== Audit endpoint called ===")
    logger.info(
        f"File: {file.filename}, UTM License: {utm_license}, MPLS L2L: {mpls_l2l}, "
        f"HA cabling redundancy: {ha_cabling_redundancy}"
    )
    
    if not file.filename or not file.filename.lower().endswith(".conf"):
        logger.error("Invalid file type")
        raise HTTPException(status_code=400, detail="Expected a FortiGate .conf file")

    contents = await file.read()
    if not contents:
        logger.error("Empty file")
        raise HTTPException(status_code=400, detail="File is empty")

    logger.info(f"File size: {len(contents)} bytes")

    # Parse WAN interfaces
    import json
    try:
        wan_list = json.loads(wan_interfaces) if wan_interfaces else None
        logger.info(f"WAN interfaces: {wan_list}")
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse WAN interfaces JSON: {e}")
        wan_list = None

    options = AuditOptions(
        utm_license=utm_license,
        mpls_l2l=mpls_l2l,
        ha_cabling_redundancy=ha_cabling_redundancy,
        wan_interfaces=wan_list,
        regle_no_match=regle_no_match,
        client_name=client_name,
        site_name=site_name,
        serial_number=serial_number,
        license_end_date=license_end_date,
        system_uptime=system_uptime,
    )

    try:
        logger.info("Starting audit process...")
        # Run complete audit
        all_results = run_complete_audit(contents, options)
        logger.info("Audit completed successfully")

        logger.info("Generating reports...")
        # Generate reports
        excel_path = generate_excel_report(
            all_results, REPORTS_DIR,
            client_name=client_name,
            site_name=site_name,
            serial_number=serial_number,
            license_end_date=license_end_date,
            system_uptime=system_uptime,
            regle_no_match=regle_no_match,
        )
        logger.info(f"Excel report generated: {excel_path}")
        word_path = generate_word_report(all_results, REPORTS_DIR,client_name=client_name,serial_number=serial_number,)
        logger.info(f"Word report generated: {word_path}")

        checks = [
            {
                "name": "Version FortiOS",
                "conform": (not all_results["version_conform"]),
            },
            {
                "name": "Modèle FortiGate",
                "conform": all_results["eol_conform"],
            },
            {
                "name": 'Rattachement à un FMG',
                "conform": all_results["sync_fortimanager_conform"],
            },
            {
                "name": "Personnalisation port HTTPS",
                "conform": all_results["is_compliant_https"],
            },
            {
                "name": 'Accès admin SNS (loopback + VIP)',
                "conform": all_results["acces_admin_sns_conform"],
            },
            {
                "name": 'Désactivation du SSH, HTTP et HTTPS sur les interfaces WAN',
                "conform": all_results["http_https_conform"],
            },
            {
                "name": 'Suppression compte "admin" par défaut',
                "conform": all_results["admin_conform"],
            },
            {
                "name": "Présence d'un compte admin local SNS avec MFA",
                "conform": all_results["admin_sns_conform"],
            },
            {
                "name": "Activation des sauvegardes automatiques",
                "conform": all_results["sauvegardes_conform"],
            },

        ]

        # Return results with download links
        response = {
            "hostname": all_results["hostname"],
            "version": all_results["version"],
            "model": all_results["model"],
            "reports": {
                "excel": f"/api/download/{excel_path.name}",
                "word": f"/api/download/{word_path.name}",
            },
            "summary": {
                "total_checks": len([k for k in all_results.keys() if k.endswith("_conform")]),
                "warnings": all_results.get("warnings", []),
            },
            "checks": checks,
        }
        logger.info("=== Audit endpoint completed successfully ===")
        return response

    except FileNotFoundError as exc:
        error_msg = f"Legacy audit file not found: {str(exc)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=error_msg) from exc
    except Exception as exc:
        error_msg = f"Audit failed: {str(exc)}"
        logger.error(error_msg)
        logger.error(f"Exception type: {type(exc).__name__}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=error_msg) from exc


@app.get("/api/download/{filename}")
async def download_report(filename: str):
    """
    Download generated report file.
    """
    # Reject anything that is not a plain file name. Without this, an encoded
    # path such as ..%2F..%2Fetc%2Fpasswd reaches this handler already decoded
    # and would escape the reports directory.
    if "/" in filename or "\\" in filename or filename in ("", ".", ".."):
        raise HTTPException(status_code=404, detail="File not found")

    reports_root = REPORTS_DIR.resolve()
    file_path = (reports_root / filename).resolve()

    # Defence in depth: confirm the resolved path really is inside reports/.
    if not file_path.is_relative_to(reports_root):
        raise HTTPException(status_code=404, detail="File not found")

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    # Determine media type
    if filename.endswith(".xlsx"):
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif filename.endswith(".docx"):
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        media_type = "application/octet-stream"

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type=media_type,
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
