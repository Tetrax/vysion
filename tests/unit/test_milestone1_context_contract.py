import pytest
from pydantic import ValidationError

from vysion.audit.models import AuditContext, ContextProvenance


def test_audit_context_keeps_operator_context_immutable_and_explicitly_unknown() -> None:
    context = AuditContext(
        selected_wans=("wan1", "wan2"),
        operator_provenance=ContextProvenance(
            source="operator-form",
            operator="analyst@example.invalid",
            method="manual-selection",
        ),
        client_name="Client synthétique",
        site_name="Paris-lab",
        ha_enabled=True,
        mpls_enabled=None,
        utm_licensed=False,
    )

    assert context.selected_wans == ("wan1", "wan2")
    assert context.client == "Client synthétique"
    assert context.site == "Paris-lab"
    assert context.ha is True
    assert context.mpls is None
    assert context.utm_license is False
    with pytest.raises(ValidationError):
        context.ha = False


def test_audit_context_does_not_invent_false_defaults() -> None:
    context = AuditContext()

    assert context.ha is None
    assert context.mpls is None
    assert context.utm_license is None
