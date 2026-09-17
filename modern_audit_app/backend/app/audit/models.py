from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class AuditOptions(BaseModel):
    utm_license: bool = True
    mpls_l2l: bool = False
    ha_cabling_redundancy: bool = False
    wan_interfaces: Optional[List[str]] = None
    regle_no_match: int = 0
    regle_no_match: int = 0
    client_name: str = ""
    site_name: str = ""
    serial_number: str = ""
    license_end_date: str = ""
    system_uptime: str = ""


class AuditResult(BaseModel):
    hostname: str
    version: Optional[str]
    model: Optional[str]
    summary: Dict[str, Any]
    warnings: List[str] = []
    reports: Dict[str, str] = {}  # download URLs (placeholder)







