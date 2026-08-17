from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, AuditFinding, AuditStatus, FortiGateConfiguration


def test_audit_engine_passes_immutable_context_to_context_aware_controls() -> None:
    received: list[AuditContext | None] = []

    def control(
        configuration: FortiGateConfiguration,
        context: AuditContext | None = None,
    ) -> AuditFinding:
        received.append(context)
        return AuditFinding(
            control_id="CTX-001",
            title="Contexte",
            status=AuditStatus.PASS,
            message=configuration.device_identity.hostname or "unknown",
        )

    context = AuditContext(selected_wans=("wan1",), client="Client synthétique")
    findings = AuditEngine((control,)).run(FortiGateConfiguration(), context)

    assert findings[0].status is AuditStatus.PASS
    assert received == [context]


def test_audit_engine_keeps_legacy_one_argument_controls_compatible() -> None:
    findings = AuditEngine(
        (
            lambda configuration: AuditFinding(
                control_id="LEGACY-001",
                title="Legacy",
                status=AuditStatus.UNKNOWN,
                message="ok",
            ),
        )
    ).run(FortiGateConfiguration(), AuditContext())

    assert findings[0].control_id == "LEGACY-001"


def test_audit_engine_converts_control_execution_failure_to_distinct_error_finding() -> None:
    def broken_control(configuration: FortiGateConfiguration) -> AuditFinding:
        raise RuntimeError("fixture failure")

    findings = AuditEngine((broken_control,)).run(FortiGateConfiguration(), AuditContext())

    assert len(findings) == 1
    assert findings[0].control_id == "ENGINE-broken_control"
    assert findings[0].status is AuditStatus.ERROR
    assert findings[0].applicability.value == "unknown"
    assert "RuntimeError" in findings[0].message
