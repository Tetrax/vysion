import inspect
from collections.abc import Callable, Iterable

from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    EvidenceItem,
    FortiGateConfiguration,
    RiskAssessment,
)

Control = Callable[..., AuditFinding]


def _stable_control_id(control: Control) -> str:
    existing = getattr(control, "control_id", None)
    if existing:
        return str(existing)
    short_name = getattr(control, "__name__", "unknown")
    # Keep ad-hoc test/application callables readable and backward compatible;
    # registered Vysion controls get a module-qualified stable identifier.
    if not getattr(control, "__module__", "").startswith("vysion."):
        return f"ENGINE-{short_name}"
    module = getattr(control, "__module__", "unknown").rsplit(".", 1)[-1]
    name = getattr(control, "__qualname__", short_name)
    normalized_name = f"{module}-{name}".replace("<", "").replace(">", "").replace(".", "-")
    normalized = "-".join(part for part in normalized_name.split() if part)
    return f"ENGINE-{normalized.upper()}"


def _control_error(control: Control, error: Exception) -> AuditFinding:
    control_name = getattr(control, "__qualname__", getattr(control, "__name__", "unknown"))
    control_id = _stable_control_id(control)
    error_type = type(error).__name__
    return AuditFinding(
        control_id=str(control_id),
        title=f"Échec d’exécution — {control_name}",
        status=AuditStatus.ERROR,
        category="engine",
        priority=AuditPriority.P0,
        severity=AuditSeverity.HIGH,
        applicability=Applicability.UNKNOWN,
        evidence=(f"exécution du contrôle interrompue: {error_type}",),
        evidence_items=(
            EvidenceItem(
                section="audit-engine",
                entry=control_name,
                directive="execution",
                tokens=(error_type,),
                certainty=EvidenceCertainty.INVALID,
            ),
        ),
        message=(
            f"Le contrôle {control_name} n’a pas pu s’exécuter ({error_type}). "
            "Aucune conclusion de conformité ne doit être tirée."
        ),
        risk=RiskAssessment(
            summary="Le contrôle n’a pas produit de résultat vérifiable.",
            impact="La couverture d’audit est incomplète.",
            likelihood="Inconnu",
            treatment="Diagnostiquer l’erreur puis rejouer l’audit.",
        ),
        recommendation="Corriger l’échec d’exécution avant d’interpréter le contrôle.",
        remediation=(
            "Consulter les journaux techniques et rejouer l’audit sur la même configuration."
        ),
    )


class AuditEngine:
    def __init__(self, controls: Iterable[Control]) -> None:
        self._controls = tuple(controls)
        for control in self._controls:
            if not getattr(control, "control_id", None):
                control.control_id = _stable_control_id(control)

    def run(
        self,
        configuration: FortiGateConfiguration,
        context: AuditContext | None = None,
    ) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        for control in self._controls:
            try:
                parameters = inspect.signature(control).parameters
                if "context" in parameters:
                    findings.append(control(configuration, context=context))
                else:
                    findings.append(control(configuration))
            except Exception as error:
                findings.append(_control_error(control, error))
        return findings
