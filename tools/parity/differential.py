from dataclasses import asdict, dataclass
from typing import Any

from tools.parity.legacy_oracle import LegacyOracle
from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


@dataclass(frozen=True, slots=True)
class DifferentialCase:
    case_id: str
    legacy_callable: str
    v2_control_id: str
    config: str
    legacy_args: list[Any] | None = None
    legacy_conform_index: int = 1
    context: dict[str, Any] | None = None
    accepted_transitions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    case_id: str
    legacy_callable: str
    v2_control_id: str
    legacy_status: str
    v2_status: str
    transition: str
    match: bool
    classification: str
    legacy_message: str
    v2_message: str
    v2_evidence: tuple[str | dict[str, Any], ...]
    affected_objects: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _legacy_status(result: Any, index: int) -> str:
    if not isinstance(result, list) or len(result) <= index:
        raise ValueError("legacy result has no configured conformity field")
    value = result[index]
    if value is True or value == "Oui":
        return "PASS"
    if value is False or value == "Non":
        return "FAIL"
    if value is None or value in {"N/A", "NOT_APPLICABLE"}:
        return "NOT_APPLICABLE"
    raise ValueError(f"unsupported legacy conformity value: {value!r}")


class DifferentialHarness:
    def __init__(self, oracle: LegacyOracle) -> None:
        self._oracle = oracle

    def run_cases(
        self,
        cases: tuple[DifferentialCase, ...],
        *,
        redact: bool = False,
    ) -> dict[str, Any]:
        results = [self.run_case(case) for case in cases]
        serialized = []
        for result in results:
            item = result.to_dict()
            if redact:
                item["legacy_message"] = "[redacted]"
                item["v2_message"] = "[redacted]"
                item["v2_evidence"] = []
                item["affected_objects"] = []
            serialized.append(item)
        matches = sum(result.match for result in results)
        semantic_equivalences = sum(
            result.classification == "SEMANTIC_EQUIVALENT" for result in results
        )
        unresolved_divergences = sum(
            result.classification == "DIVERGENCE" for result in results
        )
        return {
            "summary": {
                "total": len(results),
                "matches": matches,
                "divergences": len(results) - matches,
                "semantic_equivalences": semantic_equivalences,
                "unresolved_divergences": unresolved_divergences,
            },
            "results": serialized,
        }

    def run_case(self, case: DifferentialCase) -> DifferentialResult:
        legacy_result = self._oracle.run(
            case.legacy_callable,
            config=case.config,
            args=case.legacy_args,
        )
        legacy_status = _legacy_status(legacy_result, case.legacy_conform_index)
        configuration = FortiGateParser().parse(case.config)
        context = AuditContext.model_validate(case.context) if case.context is not None else None
        findings = AuditEngine(default_registry()).run(configuration, context=context)
        finding = next(
            (item for item in findings if item.control_id == case.v2_control_id),
            None,
        )
        if finding is None:
            raise ValueError(f"V2 control is not registered: {case.v2_control_id}")
        v2_status = finding.status.value
        transition = f"{legacy_status}->{v2_status}"
        exact_match = legacy_status == v2_status
        classification = (
            "EXACT"
            if exact_match
            else "SEMANTIC_EQUIVALENT"
            if transition in case.accepted_transitions
            else "DIVERGENCE"
        )
        message = str(legacy_result[0]) if legacy_result else ""
        return DifferentialResult(
            case_id=case.case_id,
            legacy_callable=case.legacy_callable,
            v2_control_id=case.v2_control_id,
            legacy_status=legacy_status,
            v2_status=v2_status,
            transition=transition,
            match=exact_match,
            classification=classification,
            legacy_message=message,
            v2_message=finding.message,
            v2_evidence=tuple(
                item if isinstance(item, str) else item.model_dump(mode="json")
                for item in finding.evidence
            ),
            affected_objects=tuple(
                item.model_dump(mode="json") for item in finding.affected_objects
            ),
        )
