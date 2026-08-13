from datetime import timedelta
from typing import Annotated
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse, Response

from vysion.adapters.fortiguard import FortiGuardClient, FortiGuardService
from vysion.audit.engine import AuditEngine
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry
from vysion.config import Settings
from vysion.reports.docx_report import render_docx
from vysion.reports.json_report import JsonAuditReport
from vysion.reports.xlsx_report import render_xlsx
from vysion.storage.reports import Clock, JsonReportStore, utc_now


def create_app(
    settings: Settings | None = None,
    fortiguard: FortiGuardService | None = None,
    clock: Clock = utc_now,
) -> FastAPI:
    resolved_settings = settings or Settings()
    store = JsonReportStore(resolved_settings.report_directory, clock=clock)
    parser = FortiGateParser()
    engine = AuditEngine(default_registry())
    managed_http: httpx.AsyncClient | None = None

    if fortiguard is None:
        managed_http = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
        fortiguard = FortiGuardClient(
            http=managed_http,
            status_url=resolved_settings.fortiguard_status_url,
        )

    app = FastAPI(title="Vysion", version="2.0.0", docs_url=None, redoc_url=None)
    if managed_http is not None:
        client = managed_http

        @app.on_event("shutdown")
        async def close_http_client() -> None:
            await client.aclose()

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "vysion", "version": "2"}

    @app.post("/api/audits", status_code=status.HTTP_201_CREATED)
    async def create_audit(
        configuration: Annotated[UploadFile, File()],
    ) -> JSONResponse:
        content = await configuration.read(resolved_settings.max_upload_bytes + 1)
        if len(content) > resolved_settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="configuration exceeds upload limit")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="configuration must be UTF-8") from exc
        try:
            parsed = parser.parse(text)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        created_at = clock()
        report = JsonAuditReport(
            report_id=uuid4(),
            created_at=created_at,
            expires_at=created_at + timedelta(seconds=resolved_settings.report_ttl_seconds),
            source_name=configuration.filename or "configuration.conf",
            fortiguard=await fortiguard.check(),
            findings=tuple(engine.run(parsed)),
        )
        store.save(report)
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=report.model_dump(mode="json"),
            headers={"Cache-Control": "no-store, private"},
        )

    @app.get("/api/reports/{report_id}.json")
    async def get_json_report(report_id: UUID) -> JSONResponse:
        report = store.get(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found or expired")
        return JSONResponse(
            content=report.model_dump(mode="json"),
            headers={"Cache-Control": "no-store, private"},
        )

    @app.get("/api/reports/{report_id}.docx")
    async def get_docx_report(report_id: UUID) -> Response:
        report = store.get(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found or expired")
        return Response(
            content=render_docx(report),
            media_type=(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            headers={
                "Cache-Control": "no-store, private",
                "Content-Disposition": f'attachment; filename="vysion-{report_id}.docx"',
            },
        )

    @app.get("/api/reports/{report_id}.xlsx")
    async def get_xlsx_report(report_id: UUID) -> Response:
        report = store.get(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found or expired")
        return Response(
            content=render_xlsx(report),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Cache-Control": "no-store, private",
                "Content-Disposition": f'attachment; filename="vysion-{report_id}.xlsx"',
            },
        )

    return app
