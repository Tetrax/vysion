from __future__ import annotations

import json
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditFinding,
    AuditStatus,
    FortiGateConfiguration,
)

_MAP_PATH = Path(__file__).resolve().parents[3] / "docs" / "V1_V2_CAPABILITY_MAP.json"


class PresentationRow(BaseModel):
    """One stable V1 business point in the client comparison view."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    business_key: str
    order: int
    display_name: str
    relation: str
    classification: str
    presentation_kind: str
    v2_control_ids: tuple[str, ...] = ()
    v2_projection: str | None = None
    status: AuditStatus | None = None
    applicability: Applicability | None = None
    result: str | None = None
    finding_ids: tuple[str, ...] = ()


class AuditPresentation(BaseModel):
    """Client-facing V1/V2 count and mapping contract.

    The engine still returns every internal finding.  This model gives GUI and
    exports a stable historical view without deleting or renumbering controls.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    business_control_count: int = Field(ge=0)
    engine_control_count: int = Field(ge=0)
    registered_business_count: int = Field(ge=0)
    registered_finding_count: int = Field(ge=0)
    split_extra_finding_count: int = Field(ge=0)
    v2_only_control_count: int = Field(ge=0)
    unregistered_typed_capability_count: int = Field(ge=0)
    projection_capability_count: int = Field(ge=0)
    explanation_lines: tuple[str, ...] = ()
    business_rows: tuple[PresentationRow, ...] = ()
    v2_only_rows: tuple[PresentationRow, ...] = ()
    engine_error_rows: tuple[PresentationRow, ...] = ()


@lru_cache(maxsize=1)
def _catalog() -> dict[str, Any]:
    if not _MAP_PATH.is_file():
        raise RuntimeError(f"V1/V2 presentation map not found: {_MAP_PATH}")
    payload = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
    presentation = payload.get("presentation", {})
    if presentation.get("business_control_count") != 57:
        raise RuntimeError("V1/V2 presentation map must contain 57 comparable points")
    if presentation.get("engine_control_count") != 60:
        raise RuntimeError("V1/V2 presentation map must contain 60 engine controls")
    return payload


def _legacy_rows() -> tuple[dict[str, Any], ...]:
    return tuple(
        item
        for item in _catalog()["legacy_capabilities"]
        if item.get("client_comparable") is True
    )


def _v2_only_rows() -> tuple[dict[str, Any], ...]:
    return tuple(_catalog()["v2_only_controls"])


def _control_metadata(control_id: str) -> dict[str, Any] | None:
    for item in _legacy_rows():
        targets = set(item.get("v2_targets", ()))
        if control_id in targets:
            return item
    for item in _v2_only_rows():
        if item["control_id"] == control_id:
            return item
    return None


def present_finding(finding: AuditFinding) -> AuditFinding:
    """Attach the historical client label while preserving the engine title."""

    metadata = _control_metadata(finding.control_id)
    display_name = metadata.get("display_name") if metadata else finding.title
    return finding.model_copy(update={"display_name": display_name})


def present_findings(findings: Iterable[AuditFinding]) -> tuple[AuditFinding, ...]:
    return tuple(present_finding(finding) for finding in findings)


def _aggregate_status(findings: tuple[AuditFinding, ...]) -> AuditStatus | None:
    if not findings:
        return None
    statuses = {finding.status for finding in findings}
    if AuditStatus.FAIL in statuses:
        return AuditStatus.FAIL
    if AuditStatus.ERROR in statuses or AuditStatus.UNKNOWN in statuses:
        return AuditStatus.UNKNOWN
    if statuses <= {AuditStatus.NOT_APPLICABLE}:
        return AuditStatus.NOT_APPLICABLE
    return AuditStatus.PASS


def _aggregate_applicability(findings: tuple[AuditFinding, ...]) -> Applicability | None:
    if not findings:
        return None
    statuses = {finding.status for finding in findings}
    if AuditStatus.FAIL in statuses or AuditStatus.UNKNOWN in statuses:
        return Applicability.APPLICABLE
    if statuses <= {AuditStatus.NOT_APPLICABLE}:
        return Applicability.NOT_APPLICABLE
    return Applicability.APPLICABLE


def _finding_result(findings: tuple[AuditFinding, ...]) -> str | None:
    if not findings:
        return None
    messages = tuple(dict.fromkeys(finding.message for finding in findings if finding.message))
    return " ".join(messages) if messages else None


def _typed_implementation_findings(
    configuration: FortiGateConfiguration | None,
    context: AuditContext | None,
) -> dict[str, AuditFinding]:
    if configuration is None:
        return {}
    from vysion.audit.controls.external_services import check_cti_wan_flows, check_isdb_wan_flows

    return {
        "NET-CTI-WAN-001": check_cti_wan_flows(configuration, context),
        "NET-ISDB-WAN-001": check_isdb_wan_flows(configuration, context),
    }


def _projection_result(
    row: dict[str, Any],
    configuration: FortiGateConfiguration | None,
) -> str:
    if configuration is None:
        return "Projection de données non disponible dans ce contexte."
    if row["legacy_callable"] == "exporter_utilisateurs_admins":
        return (
            f"{len(configuration.administrators)} administrateur(s) projeté(s) "
            "dans les données de l'audit."
        )
    if row["legacy_callable"] == "compter_regles_activ_ou_desactiv":
        active = sum(policy.status == "enable" for policy in configuration.policies)
        disabled = sum(policy.status == "disable" for policy in configuration.policies)
        return f"Règles actives : {active} ; règles désactivées : {disabled}."
    return "Projection de données déterministe."


def _row_for_legacy(
    row: dict[str, Any],
    findings_by_id: dict[str, AuditFinding],
    typed_findings: dict[str, AuditFinding],
    configuration: FortiGateConfiguration | None,
) -> PresentationRow:
    targets = tuple(row.get("v2_targets", ()))
    mapped = tuple(
        findings_by_id[target] for target in targets if target in findings_by_id
    )
    typed = tuple(
        typed_findings[target] for target in targets if target in typed_findings
    )
    all_findings = mapped or typed
    kind = row["presentation_kind"]
    if kind == "projection":
        return PresentationRow(
            business_key=f"V1-{row['order']:02d}",
            order=row["order"],
            display_name=row["display_name"],
            relation=row["relation"],
            classification=row["classification"],
            presentation_kind=kind,
            v2_control_ids=(),
            v2_projection=row.get("projection"),
            result=_projection_result(row, configuration),
        )
    return PresentationRow(
        business_key=f"V1-{row['order']:02d}",
        order=row["order"],
        display_name=row["display_name"],
        relation=row["relation"],
        classification=row["classification"],
        presentation_kind=kind,
        v2_control_ids=targets,
        status=_aggregate_status(all_findings),
        applicability=_aggregate_applicability(all_findings),
        result=_finding_result(all_findings)
        or (
            "Résultat produit par l'implémentation typée hors registre."
            if kind == "typed_implementation"
            else "Résultat non disponible dans ce contexte."
        ),
        finding_ids=tuple(finding.control_id for finding in all_findings),
    )


def _row_for_v2_only(
    row: dict[str, Any],
    findings_by_id: dict[str, AuditFinding],
) -> PresentationRow:
    finding = findings_by_id.get(row["control_id"])
    return PresentationRow(
        business_key=f"V2-{row['control_id']}",
        order=0,
        display_name=row["display_name"],
        relation="v2_only",
        classification="V2_ONLY",
        presentation_kind="v2_only",
        v2_control_ids=(row["control_id"],),
        status=finding.status if finding else None,
        applicability=finding.applicability if finding else None,
        result=finding.message if finding else "Résultat non disponible dans ce contexte.",
        finding_ids=(row["control_id"],) if finding else (),
    )


def build_presentation(
    findings: Iterable[AuditFinding],
    configuration: FortiGateConfiguration | None = None,
    context: AuditContext | None = None,
) -> AuditPresentation:
    presented = tuple(present_findings(findings))
    findings_by_id = {finding.control_id: finding for finding in presented}
    typed_findings = _typed_implementation_findings(configuration, context)
    rows = tuple(
        _row_for_legacy(item, findings_by_id, typed_findings, configuration)
        for item in _legacy_rows()
    )
    v2_only = tuple(_row_for_v2_only(item, findings_by_id) for item in _v2_only_rows())
    engine_errors = tuple(
        PresentationRow(
            business_key=f"ENGINE-{finding.control_id}",
            order=0,
            display_name=finding.display_name or finding.title,
            relation="engine_error",
            classification="ENGINE_ERROR",
            presentation_kind="engine_error",
            v2_control_ids=(finding.control_id,),
            status=finding.status,
            applicability=finding.applicability,
            result=finding.message,
            finding_ids=(finding.control_id,),
        )
        for finding in presented
        if finding.status is AuditStatus.ERROR
    )
    settings = _catalog()["presentation"]
    return AuditPresentation(
        business_control_count=settings["business_control_count"],
        engine_control_count=len(presented),
        registered_business_count=settings["registered_business_count"],
        registered_finding_count=settings["registered_finding_count"],
        split_extra_finding_count=settings["split_extra_finding_count"],
        v2_only_control_count=settings["v2_only_control_count"],
        unregistered_typed_capability_count=settings["unregistered_typed_capability_count"],
        projection_capability_count=settings["projection_capability_count"],
        explanation_lines=tuple(settings["explanation_lines"]),
        business_rows=rows,
        v2_only_rows=v2_only,
        engine_error_rows=engine_errors,
    )
