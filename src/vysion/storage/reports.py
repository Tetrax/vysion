import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import UUID

from vysion.clocks import Clock, utc_now
from vysion.reports.json_report import JsonAuditReport

__all__ = ["Clock", "JsonReportStore", "utc_now"]


class JsonReportStore:
    def __init__(self, directory: Path, clock: Clock = utc_now) -> None:
        self._directory = directory
        self._clock = clock
        self._directory.mkdir(parents=True, exist_ok=True)
        self.purge_expired()

    def save(self, report: JsonAuditReport) -> Path:
        self.purge_expired()
        destination = self._path(report.report_id)
        payload = report.model_dump_json(indent=2).encode("utf-8") + b"\n"
        with NamedTemporaryFile(dir=self._directory, delete=False) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.replace(destination)
        return destination

    def get(self, report_id: UUID) -> JsonAuditReport | None:
        path = self._path(report_id)
        if not path.is_file():
            return None
        report = JsonAuditReport.model_validate_json(path.read_bytes())
        if report.expires_at <= self._clock():
            path.unlink(missing_ok=True)
            return None
        return report

    def purge_expired(self) -> int:
        removed = 0
        for path in self._directory.glob("*.json"):
            try:
                report = JsonAuditReport.model_validate_json(path.read_bytes())
            except (OSError, ValueError):
                continue
            if report.expires_at <= self._clock():
                path.unlink(missing_ok=True)
                removed += 1
        return removed

    def _path(self, report_id: UUID) -> Path:
        return self._directory / f"{report_id}.json"
