"""P2 — wordings de résultat client confirmés contre la référence V1 gelée.

Chaque formulation est confirmée par exécution de l'oracle legacy
(`audit-fgt-vysion/backend/app/audit/legacy_functions.py`) ; la matrice de
décision complète est archivée hors dépôt (`audit-p2-client-wording.md`).
"""

from vysion.audit.models import (
    AffectedObject,
    Applicability,
    AuditFinding,
    AuditStatus,
)
from vysion.reports.business_text import client_result_for
from vysion.reports.docx_report import _result_explanation


def test_geo_ip_fail_uses_the_v1_reference_wording() -> None:
    finding = AuditFinding(
        control_id="NET-GEO-IP-USAGE-001",
        title="Utilisation du filtrage Geo-IP",
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        message="Aucune utilisation Geo-IP n'est détectée sur la sélection WAN.",
        evidence=("aucune policy Geo-IP",),
    )

    assert client_result_for(finding) == (
        "Aucune utilisation de GEO-IP détectée dans les règles de pare-feu."
    )


def test_geo_ip_pass_uses_the_v1_reference_wording() -> None:
    finding = AuditFinding(
        control_id="NET-GEO-IP-USAGE-001",
        title="Utilisation du filtrage Geo-IP",
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        message="Geo-IP est utilisé sur une policy liée à la sélection WAN.",
        evidence=("policies: 1, 2",),
    )

    assert client_result_for(finding) == (
        "GEO-IP est utilisé dans les règles de pare-feu. "
        "Il peut être pertinent d'actualiser le filtrage GEO-IP."
    )


def test_geo_ip_unknown_keeps_the_engine_message() -> None:
    finding = AuditFinding(
        control_id="NET-GEO-IP-USAGE-001",
        title="Utilisation du filtrage Geo-IP",
        status=AuditStatus.UNKNOWN,
        applicability=Applicability.UNKNOWN,
        message="Sélection WAN typed absente.",
    )

    assert client_result_for(finding) == "Sélection WAN typed absente"


def test_utm_fail_uses_the_v1_reference_wording_and_rule_ids() -> None:
    finding = AuditFinding(
        control_id="FW-UTM-PROFILE-BINDING-001",
        title="Profils de sécurité sur les règles UTM",
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        message="Une politique logtraffic utm activée n'a pas de binding UTM valide.",
        affected_objects=(
            AffectedObject(name="4", object_type="firewall-policy"),
            AffectedObject(name="7", object_type="firewall-policy"),
        ),
    )

    assert client_result_for(finding) == (
        "Des règles avec logs en UTM n'ont pas de profil de sécurité activé. "
        "Règles concernées : 4, 7."
    )


def test_utm_pass_uses_the_v1_reference_wording_and_rule_ids() -> None:
    finding = AuditFinding(
        control_id="FW-UTM-PROFILE-BINDING-001",
        title="Profils de sécurité sur les règles UTM",
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        message="Les bindings UTM des politiques logtraffic utm sont résolus et actifs.",
        affected_objects=(AffectedObject(name="4", object_type="firewall-policy"),),
    )

    assert client_result_for(finding) == (
        "Les règles avec logs en UTM disposent de profils de sécurité activés. "
        "Règles concernées : 4."
    )


def test_utm_not_applicable_keeps_the_generic_wording() -> None:
    finding = AuditFinding(
        control_id="FW-UTM-PROFILE-BINDING-001",
        title="Profils de sécurité sur les règles UTM",
        status=AuditStatus.PASS,
        applicability=Applicability.NOT_APPLICABLE,
        message="Aucune politique logtraffic utm applicable n'est déclarée.",
    )

    assert _result_explanation(finding) == ("Ce point n'est pas applicable au périmètre analysé.")


def test_vpn_ssl_not_applicable_uses_the_v1_reference_wording() -> None:
    finding = AuditFinding(
        control_id="VPN-SSL-001",
        title="État et usage explicites du SSL-VPN",
        status=AuditStatus.PASS,
        applicability=Applicability.NOT_APPLICABLE,
        message="Le VPN SSL n'est pas utilisé selon la règle historique V1.",
    )

    assert _result_explanation(finding) == "Le VPN SSL n'est pas utilisé."


def test_vpn_ssl_applicable_fail_keeps_the_engine_message() -> None:
    finding = AuditFinding(
        control_id="VPN-SSL-001",
        title="État et usage explicites du SSL-VPN",
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        message="Une activation ou une utilisation SSL-VPN est explicitement présente.",
    )

    assert _result_explanation(finding) == (
        "Une activation ou une utilisation SSL-VPN est explicitement présente"
    )


def test_cfg_unused_keeps_the_engine_message_and_detected_objects() -> None:
    finding = AuditFinding(
        control_id="CFG-UNUSED-SERVICE-001",
        title="Objets sans référence",
        status=AuditStatus.FAIL,
        applicability=Applicability.APPLICABLE,
        message="Des objets de configuration certains ne sont référencés par aucun usage prouvé.",
        affected_objects=(
            AffectedObject(name="OBJET_ORPHELIN", object_type="address"),
            AffectedObject(name="ZONE_INUTILISEE", object_type="zone"),
        ),
    )

    assert client_result_for(finding) == (
        "Des objets de configuration confirmés ne sont référencés par aucun usage prouvé. "
        "Éléments détectés : OBJET_ORPHELIN, ZONE_INUTILISEE."
    )
