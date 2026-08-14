import inspect
from collections.abc import Callable, Iterable

from vysion.audit.models import AuditContext, AuditFinding, FortiGateConfiguration

Control = Callable[..., AuditFinding]


class AuditEngine:
    def __init__(self, controls: Iterable[Control]) -> None:
        self._controls = tuple(controls)

    def run(
        self,
        configuration: FortiGateConfiguration,
        context: AuditContext | None = None,
    ) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        for control in self._controls:
            parameters = inspect.signature(control).parameters
            if "context" in parameters:
                findings.append(control(configuration, context=context))
            else:
                findings.append(control(configuration))
        return findings
