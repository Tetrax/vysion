from collections.abc import Callable, Iterable

from vysion.audit.models import AuditFinding, FortiGateConfiguration

Control = Callable[[FortiGateConfiguration], AuditFinding]


class AuditEngine:
    def __init__(self, controls: Iterable[Control]) -> None:
        self._controls = tuple(controls)

    def run(self, configuration: FortiGateConfiguration) -> list[AuditFinding]:
        return [control(configuration) for control in self._controls]
