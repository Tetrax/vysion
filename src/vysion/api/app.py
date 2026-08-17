import json
from collections.abc import Iterable
from datetime import date, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse, Response

from vysion.adapters.fortiguard import (
    FortiGuardClient,
    FortiGuardService,
    error_psirt_observation,
)
from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AuditContext,
    ContextProvenance,
    FortiGateConfiguration,
    ProofState,
    PsirtObservation,
    RuleMatchStatistics,
    UtmLicenseDetails,
    UtmLicenseStatus,
    WanSelection,
    WanSelectionKind,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry
from vysion.config import Settings
from vysion.reports.docx_report import render_docx
from vysion.reports.json_report import AccountMetadata, EquipmentMetadata, JsonAuditReport
from vysion.reports.xlsx_report import render_xlsx
from vysion.storage.reports import Clock, JsonReportStore, utc_now

VYSION_VERSION = "2.2.0-dev"


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


def _optional_nonnegative_int(value: str | None, field_name: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        parsed = int(value.strip())
    except (AttributeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be an integer") from exc
    if parsed < 0:
        raise HTTPException(status_code=422, detail=f"{field_name} must be non-negative")
    return parsed


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


def _unique_named(items: Iterable[Any]) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    duplicates: set[str] = set()
    for item in items:
        key = item.name.casefold()
        if key in duplicates:
            continue
        if key in resolved:
            duplicates.add(key)
            resolved.pop(key)
            continue
        resolved[key] = item
    return resolved


def _resolve_interface_references(
    references: Iterable[Any],
    interfaces: dict[str, Any],
) -> tuple[str, ...]:
    resolved: list[str] = []
    seen: set[str] = set()
    for reference in references:
        key = reference.name.casefold()
        interface = interfaces.get(key)
        if interface is None or key in seen:
            return ()
        seen.add(key)
        resolved.append(interface.name)
    return tuple(resolved) if resolved else ()


def _selected_wan_scopes(
    values: Iterable[str],
    configuration: FortiGateConfiguration,
) -> tuple[WanSelection, ...] | None:
    raw_items: list[object] = []
    explicit_json_list = False
    for value in values:
        if not value.strip():
            continue
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=422,
                detail="selected_wan_scopes must be valid JSON",
            ) from exc
        if isinstance(decoded, list):
            explicit_json_list = True
            raw_items.extend(decoded)
        elif isinstance(decoded, dict):
            raw_items.append(decoded)
        else:
            raise HTTPException(
                status_code=422,
                detail="selected_wan_scopes must be a JSON list of objects",
            )
    if not raw_items:
        return () if explicit_json_list else None

    interfaces = _unique_named(configuration.interfaces)
    zones = _unique_named(configuration.zones)
    sdwan_zones = _unique_named(configuration.sdwan_zones)
    selections: list[WanSelection] = []
    seen: set[tuple[str, str]] = set()
    for item in raw_items:
        if not isinstance(item, dict) or set(item) - {"name", "kind"}:
            raise HTTPException(
                status_code=422,
                detail="each selected_wan_scope must contain only name and kind",
            )
        name = item.get("name")
        kind_value = item.get("kind")
        if not isinstance(name, str) or not name.strip() or not isinstance(kind_value, str):
            raise HTTPException(
                status_code=422,
                detail="each selected_wan_scope needs a non-empty name and kind",
            )
        try:
            kind = WanSelectionKind(kind_value.casefold())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid WAN selection kind") from exc
        normalized_name = name.strip()
        unique_key = (kind.value, normalized_name.casefold())
        if unique_key in seen:
            raise HTTPException(status_code=422, detail="WAN selections must be unique")
        seen.add(unique_key)

        resolved_interfaces: tuple[str, ...] = ()
        if kind is WanSelectionKind.INTERFACE:
            resolved = interfaces.get(normalized_name.casefold())
            resolved_interfaces = (resolved.name,) if resolved is not None else ()
        elif kind is WanSelectionKind.ZONE:
            zone = zones.get(normalized_name.casefold())
            if zone is not None and zone.proof_state is ProofState.PROVEN:
                resolved_interfaces = _resolve_interface_references(zone.interfaces, interfaces)
        elif kind is WanSelectionKind.SDWAN:
            zone = sdwan_zones.get(normalized_name.casefold())
            if zone is not None and zone.proof_state is ProofState.PROVEN:
                resolved_interfaces = _resolve_interface_references(zone.interfaces, interfaces)
        else:
            if normalized_name.casefold() != "automatic":
                raise HTTPException(
                    status_code=422,
                    detail="automatic WAN selection must be named automatic",
                )
            resolved_interfaces = tuple(
                interface.name
                for interface in configuration.interfaces
                if interface.role is not None and interface.role.casefold() == "wan"
            )
        selections.append(
            WanSelection(
                name=normalized_name,
                kind=kind,
                interfaces=resolved_interfaces,
            )
        )
    return tuple(selections)


def _utm_license_details(
    *,
    legacy: str | None,
    status_value: str | None,
    expiration_value: str | None,
    provenance: str | None,
    manual_value: str | None,
) -> UtmLicenseDetails | None:
    values = (status_value, expiration_value, provenance, manual_value)
    if not any(value is not None for value in values):
        return None
    if status_value is None:
        raise HTTPException(status_code=422, detail="utm_license_status is required")
    try:
        status = UtmLicenseStatus(status_value.strip().casefold())
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="utm_license_status must be active or inactive",
        ) from exc
    expiration = None
    if expiration_value:
        try:
            expiration = date.fromisoformat(expiration_value.strip())
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="utm_license_expiration must be an ISO date",
            ) from exc
    manual = _optional_bool(manual_value, "utm_license_manual")
    if legacy is not None and _optional_bool(legacy, "utm_license") != (
        status is UtmLicenseStatus.ACTIVE
    ):
        raise HTTPException(
            status_code=422,
            detail="utm_license conflicts with utm_license_status",
        )
    return UtmLicenseDetails(
        status=status,
        expiration_date=expiration,
        provenance=provenance,
        manual=False if manual is None else manual,
    )


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
    selected_wan_scopes: Iterable[str] = (),
    configuration: FortiGateConfiguration,
    client: str | None,
    site: str | None,
    serial_number: str | None,
    uptime: str | None,
    unmatched_rules: str | None,
    operator_comment: str | None,
    operator: str | None,
    ha: str | None,
    mpls: str | None,
    utm_license: str | None,
    utm_license_status: str | None,
    utm_license_expiration: str | None,
    utm_license_provenance: str | None,
    utm_license_manual: str | None,
    operator_context: str | None = None,
    context_source: str | None,
    context_operator: str | None,
    context_method: str | None,
) -> AuditContext:
    selected = _selected_wans(selected_wans)
    typed_selections = _selected_wan_scopes(selected_wan_scopes, configuration)
    if typed_selections is not None:
        typed_names = tuple(selection.name for selection in typed_selections)
        if selected and sorted(name.casefold() for name in selected) != sorted(
            name.casefold() for name in typed_names
        ):
            raise HTTPException(
                status_code=422,
                detail="selected_wans conflicts with selected_wan_scopes",
            )
        selected = typed_names
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
    license_details = _utm_license_details(
        legacy=utm_license,
        status_value=utm_license_status,
        expiration_value=utm_license_expiration,
        provenance=utm_license_provenance,
        manual_value=utm_license_manual,
    )
    unmatched_value = _optional_nonnegative_int(unmatched_rules, "unmatched_rules")
    rule_match_statistics = (
        RuleMatchStatistics(unmatched_rules=unmatched_value)
        if unmatched_value is not None
        else None
    )
    return AuditContext(
        selected_wans=selected,
        wan_selections=typed_selections,
        operator_provenance=provenance,
        client=client,
        site=site,
        serial_number=serial_number,
        uptime=uptime,
        operator_comment=operator_comment,
        rule_match_statistics=rule_match_statistics,
        operator=operator,
        utm_license_details=license_details,
        **booleans,
    )


async def _read_parsed_configuration(
    configuration: UploadFile,
    *,
    max_upload_bytes: int,
    parser: FortiGateParser,
):
    content = await configuration.read(max_upload_bytes + 1)
    if len(content) > max_upload_bytes:
        raise HTTPException(status_code=413, detail="configuration exceeds upload limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="configuration must be UTF-8") from exc
    try:
        return parser.parse(text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _preview_zone_payload(
    zones: Iterable[Any],
    interfaces: dict[str, Any],
    *,
    sort_interfaces: bool = False,
) -> list[dict[str, object]]:
    preview: list[dict[str, object]] = []
    for zone in _unique_named(zones).values():
        if zone.proof_state is not ProofState.PROVEN:
            continue
        resolved_interfaces = _resolve_interface_references(zone.interfaces, interfaces)
        if not resolved_interfaces:
            continue
        preview.append(
            {
                "name": zone.name,
                "interfaces": (
                    sorted(resolved_interfaces)
                    if sort_interfaces
                    else list(resolved_interfaces)
                ),
            }
        )
    return preview


def _preview_sdwan_zones(configuration) -> list[dict[str, object]]:
    interfaces = _unique_named(configuration.interfaces)
    return _preview_zone_payload(
        configuration.sdwan_zones,
        interfaces,
        sort_interfaces=True,
    )


def _equipment_metadata(configuration: FortiGateConfiguration) -> EquipmentMetadata:
    identity = configuration.device_identity
    return EquipmentMetadata(
        hostname=identity.hostname,
        model=identity.model,
        firmware_version=identity.firmware_version,
        serial_number=identity.serial_number,
        interface_names=tuple(interface.name for interface in configuration.interfaces),
        zone_names=tuple(zone.name for zone in configuration.zones),
        sdwan_zone_names=tuple(zone.name for zone in configuration.sdwan_zones),
        interface_zone_relations=tuple(
            f"{interface.name} → {interface.zone.name}"
            for interface in configuration.interfaces
            if interface.zone is not None
        ),
    )


def _account_metadata(configuration: FortiGateConfiguration) -> tuple[AccountMetadata, ...]:
    administrators = tuple(
        AccountMetadata(
            name=account.name,
            kind="administrator",
            two_factor=account.two_factor,
            peer_auth=None if account.peer_auth is None else str(account.peer_auth),
        )
        for account in configuration.administrators
    )
    local_users = tuple(
        AccountMetadata(
            name=account.name,
            kind="local-user",
            two_factor=account.two_factor,
        )
        for account in configuration.local_users
    )
    return administrators + local_users


def _preview_payload(configuration) -> dict[str, object]:
    identity = configuration.device_identity
    preview_interfaces = tuple(_unique_named(configuration.interfaces).values())
    interface_index = _unique_named(configuration.interfaces)
    preview_zones = _preview_zone_payload(configuration.zones, interface_index)
    return {
        "hostname": identity.hostname,
        "model": identity.model,
        "firmware_version": identity.firmware_version,
        "serial_number": identity.serial_number,
        "interfaces": [
            {
                "name": interface.name,
                "role": interface.role,
            }
            for interface in preview_interfaces
        ],
        "zones": preview_zones,
        "wan_relations": [
            {"interface": interface.name, "zone": interface.zone.name}
            for interface in preview_interfaces
            if interface.zone is not None
        ],
        "sdwan_zones": _preview_sdwan_zones(configuration),
    }


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

    app = FastAPI(title="Vysion", version=VYSION_VERSION, docs_url=None, redoc_url=None)
    if managed_http is not None:
        client = managed_http

        @app.on_event("shutdown")
        async def close_http_client() -> None:
            await client.aclose()

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "vysion", "version": VYSION_VERSION}

    @app.post("/api/audits/preview")
    async def preview_audit(configuration: Annotated[UploadFile, File()]) -> JSONResponse:
        parsed = await _read_parsed_configuration(
            configuration,
            max_upload_bytes=resolved_settings.max_upload_bytes,
            parser=parser,
        )
        return JSONResponse(
            content=_preview_payload(parsed),
            headers={"Cache-Control": "no-store, private"},
        )

    @app.post("/api/audits", status_code=status.HTTP_201_CREATED)
    async def create_audit(
        configuration: Annotated[UploadFile, File()],
        request: Request,
    ) -> JSONResponse:
        form = await request.form()
        selected_wans = _text_values(form.getlist("selected_wans"), "selected_wans")
        selected_wan_scopes = _text_values(
            form.getlist("selected_wan_scopes"), "selected_wan_scopes"
        )
        client = _optional_form_value(form.getlist("client"), "client")
        site = _optional_form_value(form.getlist("site"), "site")
        serial_number = _optional_form_value(form.getlist("serial_number"), "serial_number")
        uptime = _optional_form_value(form.getlist("uptime"), "uptime")
        unmatched_rules = _optional_form_value(
            form.getlist("unmatched_rules"), "unmatched_rules"
        )
        operator_comment = _optional_form_value(
            form.getlist("context_comment") or form.getlist("comment"), "context_comment"
        )
        operator = _optional_form_value(form.getlist("operator"), "operator")
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
        utm_license_status = _optional_form_value(
            form.getlist("utm_license_status"), "utm_license_status"
        )
        utm_license_expiration = _optional_form_value(
            form.getlist("utm_license_expiration"), "utm_license_expiration"
        )
        utm_license_provenance = _optional_form_value(
            form.getlist("utm_license_provenance"), "utm_license_provenance"
        )
        utm_license_manual = _optional_form_value(
            form.getlist("utm_license_manual"), "utm_license_manual"
        )
        context_source = _optional_form_value(form.getlist("context_source"), "context_source")
        context_operator = _optional_form_value(
            form.getlist("context_operator"), "context_operator"
        )
        context_method = _optional_form_value(form.getlist("context_method"), "context_method")
        parsed = await _read_parsed_configuration(
            configuration,
            max_upload_bytes=resolved_settings.max_upload_bytes,
            parser=parser,
        )

        context = _audit_context(
            selected_wans=selected_wans,
            selected_wan_scopes=selected_wan_scopes,
            configuration=parsed,
            client=client,
            site=site,
            serial_number=serial_number,
            uptime=uptime,
            unmatched_rules=unmatched_rules,
            operator_comment=operator_comment,
            operator=operator,
            ha=ha,
            mpls=mpls,
            utm_license=utm_license,
            utm_license_status=utm_license_status,
            utm_license_expiration=utm_license_expiration,
            utm_license_provenance=utm_license_provenance,
            utm_license_manual=utm_license_manual,
            operator_context=operator_context,
            context_source=context_source,
            context_operator=context_operator,
            context_method=context_method,
        )
        firmware_version = parsed.device_identity.firmware_version
        if firmware_version is not None:
            try:
                psirt = PsirtObservation.model_validate(
                    await fortiguard.check_psirt(firmware_version)
                )
            except Exception:
                psirt = error_psirt_observation(firmware_version)
            context = context.model_copy(
                update={"psirt": psirt}
            )

        created_at = clock()
        report = JsonAuditReport(
            report_id=uuid4(),
            created_at=created_at,
            expires_at=created_at + timedelta(seconds=resolved_settings.report_ttl_seconds),
            source_name=configuration.filename or "configuration.conf",
            context=context,
            equipment=_equipment_metadata(parsed),
            accounts=_account_metadata(parsed),
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
