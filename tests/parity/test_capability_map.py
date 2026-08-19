import json
from pathlib import Path

from vysion.audit.engine import AuditEngine
from vysion.audit.models import FortiGateConfiguration
from vysion.audit.registry import default_registry

ROOT = Path(__file__).parents[2]
MAPPING = ROOT / "docs" / "V1_V2_CAPABILITY_MAP.json"


def _registry_ids() -> tuple[str, ...]:
    findings = AuditEngine(default_registry()).run(FortiGateConfiguration())
    return tuple(finding.control_id for finding in findings)


def test_capability_map_is_exhaustive_and_matches_current_registry() -> None:
    payload = json.loads(MAPPING.read_text(encoding="utf-8"))
    capabilities = payload["legacy_capabilities"]
    registry_ids = _registry_ids()

    assert payload["legacy_oracle"]["business_capability_count"] == 59
    assert payload["v2_registry"]["finding_count"] == 60
    assert len(capabilities) == 59
    assert [item["order"] for item in capabilities] == list(range(1, 60))
    assert len({item["legacy_callable"] for item in capabilities}) == 59
    assert len(registry_ids) == len(set(registry_ids)) == 60
    assert tuple(payload["v2_registry"]["control_ids"]) == registry_ids

    mapped = {
        control_id
        for item in capabilities
        for control_id in item["v2_control_ids"]
    }
    v2_only = {item["control_id"] for item in payload["v2_only_controls"]}
    assert mapped | v2_only == set(registry_ids)
    assert mapped & v2_only == set()


def test_capability_map_classifies_splits_and_unregistered_paths() -> None:
    payload = json.loads(MAPPING.read_text(encoding="utf-8"))
    by_callable = {
        item["legacy_callable"]: item for item in payload["legacy_capabilities"]
    }

    assert by_callable["verifier_mfa_utilisateurs_admins"]["relation"] == "split"
    assert by_callable["verifier_durcissement_vpn_ipsec_split"]["relation"] == "split"
    assert by_callable["verifier_presence_cti"]["disposition"] == "OFF_REGISTRY"
    assert by_callable["verifier_presence_isdb"]["disposition"] == "OFF_REGISTRY"
    assert by_callable["verifier_modele_fortigate_eol"]["disposition"] == "BLOCKED_EXTERNAL_SOURCE"
    assert by_callable["verifier_logs_par_regle"]["disposition"] == "BLOCKED_RUNTIME_DATA"
