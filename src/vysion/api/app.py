import json
from collections.abc import Iterable
from datetime import timedelta
from typing import Annotated
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse, Response

from vysion.adapters.fortiguard import FortiGuardClient, FortiGuardService
from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, ContextProvenance
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry
from vysion.config import Settings
from vysion.reports.docx_report import render_docx
from vysion.reports.json_report import JsonAuditReport
from vysion.reports.xlsx_report import render_xlsx
from vysion.storage.reports import Clock, JsonReportStore, utc_now


def _optional_bool(value: str | None, field_name: str) -> bool | None:
    if value is None or value == "":
        return None
    normalized = value.strip().casefold()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    if normalized in {"unknown", "unset", "none", "null"}:
        return None
    raise HTTPException(status_code=422, detail=f"{field_name} must be true or false")


def _selected_wans(values: Iterable[str]) -> tuple[str, ...] | None:
    flattened: list[str] = []
    explicit_json_list = False
    for value in values:
        if not value.strip():
            continue
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            if value.lstrip().startswith(("[", "{")):
                raise HTTPException(
                    status_code=422,
                    detail="selected_wans must be valid JSON when sent as JSON",
                ) from exc
            decoded = value
        if isinstance(decoded, list):
            explicit_json_list = True
            if any(not isinstance(item, str) for item in decoded):
                raise HTTPException(
                    status_code=422,
                    detail="selected_wans must be a JSON list of strings",
                )
            flattened.extend(decoded)
        elif isinstance(decoded, str):
            flattened.extend(decoded.split(","))
        else:
            raise HTTPException(
                status_code=422,
                detail="selected_wans must be a string or JSON list of strings",
            )
    if not flattened:
        return () if explicit_json_list else None
    normalized = tuple(item.strip() for item in flattened)
    if any(not item for item in normalized) or len(
        set(map(str.casefold, normalized))
    ) != len(normalized):
        raise HTTPException(
            status_code=422,
            detail="selected_wans must contain unique non-empty names",
        )
    return normalized


def _text_values(values: Iterable[object], field_name: str) -> list[str]:
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise HTTPException(status_code=422, detail=f"{field_name} must be text")
        result.append(value)
    return result


def _optional_form_value(values: Iterable[object], field_name: str) -> str | None:
    non_empty = [value for value in _text_values(values, field_name) if value != ""]
    if len(non_empty) > 1:
        raise HTTPException(status_code=422, detail=f"{field_name} must be supplied once")
    return non_empty[0] if non_empty else None


def _operator_provenance(
    operator_context: str | None,
    *,
    context_source: str | None,
    context_operator: str | None,
    context_method: str | None,
) -> ContextProvenance | None:
    if operator_context is not None:
        try:
            decoded = json.loads(operator_context)
        except json.JSONDecodeError:
            decoded = operator_context
        if isinstance(decoded, str):
            return ContextProvenance(source=decoded)
        if not isinstance(decoded, dict):
            raise HTTPException(
                status_code=422,
                detail="operator_context must be an object or string",
            )
        try:
            return ContextProvenance.model_validate(decoded)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid operator_context") from exc

    provenance_values = (context_source, context_operator, context_method)
    if any(value is not None for value in provenance_values):
        if not context_source:
            raise HTTPException(status_code=422, detail="context_source is required for provenance")
        try:
            return ContextProvenance(
                source=context_source,
                operator=context_operator,
                method=context_method,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid context provenance") from exc
    return None


def _audit_context(
    *,
    selected_wans: Iterable[str],
    client: str | None,
    site: str | None,
    ha: str | None,
    mpls: str | None,
    utm_license: str | None,
    operator_context: str | None = None,
    context_source: str | None,
    context_operator: str | None,
    context_method: str | None,
) -> AuditContext:
    selected = _selected_wans(selected_wans)
    booleans = {
        "ha": _optional_bool(ha, "ha"),
        "mpls": _optional_bool(mpls, "mpls"),
        "utm_license": _optional_bool(utm_license, "utm_license"),
    }
    provenance = _operator_provenance(
        operator_context,
        context_source=context_source,
        context_operator=context_operator,
        context_method=context_method,
    )
    return AuditContext(
        selected_wans=selected,
        operator_provenance=provenance,
        client=client,
        site=site,
        **booleans,
    )


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
        request: Request,
    ) -> JSONResponse:
        form = await request.form()
        selected_wans = _text_values(form.getlist("selected_wans"), "selected_wans")
        client = _optional_form_value(form.getlist("client"), "client")
        site = _optional_form_value(form.getlist("site"), "site")
        operator_context = _optional_form_value(
            form.getlist("operator_context"), "operator_context"
        )
        ha = _optional_form_value(
            form.getlist("ha_context") or form.getlist("ha"), "ha_context"
        )
        mpls = _optional_form_value(
            form.getlist("mpls_context") or form.getlist("mpls"), "mpls_context"
        )
        utm_license = _optional_form_value(form.getlist("utm_license"), "utm_license")
        context_source = _optional_form_value(form.getlist("context_source"), "context_source")
        context_operator = _optional_form_value(
            form.getlist("context_operator"), "context_operator"
        )
        context_method = _optional_form_value(form.getlist("context_method"), "context_method")
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

        context = _audit_context(
            selected_wans=selected_wans,
            client=client,
            site=site,
            ha=ha,
            mpls=mpls,
            utm_license=utm_license,
            operator_context=operator_context,
            context_source=context_source,
            context_operator=context_operator,
            context_method=context_method,
        )

        created_at = clock()
        report = JsonAuditReport(
            report_id=uuid4(),
            created_at=created_at,
            expires_at=created_at + timedelta(seconds=resolved_settings.report_ttl_seconds),
            source_name=configuration.filename or "configuration.conf",
            context=context,
            fortiguard=await fortiguard.check(),
            findings=tuple(engine.run(parsed, context=context)),
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
