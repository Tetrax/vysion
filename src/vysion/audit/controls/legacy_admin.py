from __future__ import annotations

from collections.abc import Iterable

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
    LegacyV1AdminPolicy,
    ProofState,
    RiskAssessment,
    StructuralEntry,
)

_PROVENANCE = "legacy_v1"


def _finding(
    control_id: str,
    title: str,
    status: AuditStatus,
    message: str,
    evidence: tuple[str, ...],
    evidence_items: tuple[EvidenceItem, ...],
) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="legacy-administration",
        priority=AuditPriority.P1,
        severity=AuditSeverity.HIGH,
        applicability=(
            Applicability.UNKNOWN if status is AuditStatus.UNKNOWN else Applicability.APPLICABLE
        ),
        evidence=evidence,
        evidence_items=evidence_items,
        message=message,
        risk=RiskAssessment(
            summary="La règle d’administration historique V1 doit être conservée.",
            impact="Un accès d’administration attendu peut être absent ou insuffisamment protégé.",
            likelihood="indéterminée" if status is AuditStatus.UNKNOWN else "moyenne",
            treatment="Appliquer la policy opérateur puis rejouer l’audit.",
        ),
        recommendation="Aligner la configuration sur la policy legacy_v1 approuvée.",
        remediation="Corriger les objets concernés et relancer le contrôle structurel.",
        rule_provenance=_PROVENANCE,
    )


def _policy(context: AuditContext | None) -> LegacyV1AdminPolicy | None:
    if (
        context is None
        or context.operator_provenance is None
        or not context.operator_provenance.source.strip()
    ):
        return None
    return context.legacy_v1_admin_policy


def _unknown(control_id: str, title: str, section: str, reason: str) -> AuditFinding:
    return _finding(
        control_id,
        title,
        AuditStatus.UNKNOWN,
        reason,
        (reason,),
        (
            EvidenceItem(
                section=section,
                directive="legacy-policy",
                tokens=(_PROVENANCE,),
                certainty=EvidenceCertainty.INVALID,
            ),
        ),
    )


def _entry_directive(entry: StructuralEntry, name: str) -> tuple[str, ...] | None:
    if entry.certainty is not EvidenceCertainty.CERTAIN or name in entry.invalidated_keys:
        return None
    matches = tuple(
        directive
        for directive in entry.directives
        if directive.name == name
        and not directive.mutation
        and directive.certainty is EvidenceCertainty.CERTAIN
    )
    return matches[0].tokens if len(matches) == 1 else None


def _entry_item(section: str, entry: StructuralEntry, directive: str) -> EvidenceItem:
    return EvidenceItem(
        section=section,
        entry=entry.name,
        directive=directive,
        line=entry.line,
        certainty=entry.certainty,
    )


def check_legacy_local_admin(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "IAM-LEGACY-ADMIN-001"
    title = "Compte administrateur local historique"
    policy = _policy(context)
    section = configuration.document.section("system admin")
    if policy is None:
        return _unknown(control_id, title, "system admin", "Policy opérateur legacy_v1 absente.")
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return _unknown(
            control_id, title, "system admin", "Namespace system admin absent ou ambigu."
        )

    aliases = {name.casefold() for name in policy.local_admin_names}
    matches = tuple(entry for entry in section.entries if entry.name.casefold() in aliases)
    if any(entry.certainty is not EvidenceCertainty.CERTAIN for entry in matches):
        return _unknown(control_id, title, "system admin", "Compte historique ambigu.")
    for entry in matches:
        password = _entry_directive(entry, "password")
        peer_group = _entry_directive(entry, "peer-group")
        if password is None or peer_group == (policy.pki_peer_group,):
            continue
        two_factor = _entry_directive(entry, "two-factor")
        email_to = _entry_directive(entry, "email-to")
        passed = (
            two_factor is not None
            and tuple(value.casefold() for value in two_factor) == ("email",)
            and email_to == (policy.local_admin_mfa_email,)
        )
        return _finding(
            control_id,
            title,
            AuditStatus.PASS if passed else AuditStatus.FAIL,
            "Le compte local historique et son MFA email sont conformes."
            if passed
            else "Le compte local historique existe mais son MFA email n’est pas conforme.",
            (f"compte ciblé: {entry.name}", "policy: legacy_v1"),
            (_entry_item("system admin", entry, "two-factor"),),
        )
    return _finding(
        control_id,
        title,
        AuditStatus.FAIL,
        "Aucun compte administrateur local correspondant à la policy n’est présent.",
        ("aucun alias local conforme", "policy: legacy_v1"),
        (EvidenceItem(section="system admin", directive="password"),),
    )


def _pki_control(
    configuration: FortiGateConfiguration,
    context: AuditContext | None,
    *,
    control_id: str,
    title: str,
    target_attribute: str,
    expected_present: bool,
) -> AuditFinding:
    policy = _policy(context)
    section = configuration.document.section("system admin")
    if policy is None:
        return _unknown(control_id, title, "system admin", "Policy opérateur legacy_v1 absente.")
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return _unknown(
            control_id, title, "system admin", "Namespace system admin absent ou ambigu."
        )
    target = getattr(policy, target_attribute)
    matches = tuple(
        entry for entry in section.entries if entry.name.casefold() == target.casefold()
    )
    if any(entry.certainty is not EvidenceCertainty.CERTAIN for entry in matches):
        return _unknown(control_id, title, "system admin", "Compte PKI ciblé ambigu.")
    enabled = tuple(
        entry
        for entry in matches
        if _entry_directive(entry, "peer-group") is not None
        or tuple(value.casefold() for value in (_entry_directive(entry, "peer-auth") or ()))
        == ("enable",)
    )
    passed = bool(enabled) is expected_present
    return _finding(
        control_id,
        title,
        AuditStatus.PASS if passed else AuditStatus.FAIL,
        "La présence du compte PKI correspond à la règle historique."
        if passed
        else "La présence du compte PKI ne correspond pas à la règle historique.",
        (f"cible PKI configurée: {target}", "policy: legacy_v1"),
        tuple(_entry_item("system admin", entry, "peer-auth") for entry in enabled)
        or (EvidenceItem(section="system admin", entry=target, directive="peer-auth"),),
    )


def check_legacy_pki_removal(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    return _pki_control(
        configuration,
        context,
        control_id="IAM-LEGACY-PKI-REMOVAL-001",
        title="Suppression du compte PKI historique",
        target_attribute="deprecated_pki_account",
        expected_present=False,
    )


def check_legacy_pki_presence(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    return _pki_control(
        configuration,
        context,
        control_id="IAM-LEGACY-PKI-PRESENCE-001",
        title="Présence du compte PKI géré",
        target_attribute="required_pki_account",
        expected_present=True,
    )


def _all_proven(values: Iterable[object]) -> bool:
    return all(
        getattr(value, "proof_state", ProofState.UNKNOWN) is ProofState.PROVEN for value in values
    )


def check_legacy_admin_loopback(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "NET-LEGACY-ADMIN-LOOPBACK-001"
    title = "Accès d’administration historique via loopback"
    policy = _policy(context)
    required_sections = (
        "system interface",
        "firewall address",
        "firewall addrgrp",
        "firewall vip",
        "firewall policy",
    )
    if policy is None:
        return _unknown(control_id, title, "firewall policy", "Policy opérateur legacy_v1 absente.")
    sections = tuple(configuration.document.section(name) for name in required_sections)
    if any(
        section is None or section.certainty is not EvidenceCertainty.CERTAIN
        for section in sections
    ):
        return _unknown(
            control_id, title, "firewall policy", "Namespaces d’accès admin absents ou ambigus."
        )
    projected = (
        *configuration.address_objects,
        *configuration.address_groups,
        *configuration.vips,
        *configuration.vip_groups,
        *configuration.policies,
    )
    if not _all_proven(projected):
        return _unknown(
            control_id, title, "firewall policy", "Projection d’accès admin incomplète."
        )

    fqdn_objects = {
        item.name.casefold()
        for item in configuration.address_objects
        if item.address_type == "fqdn"
        and item.fqdn is not None
        and policy.administration_fqdn.casefold() in item.fqdn.casefold()
    }
    source_groups = {
        group.name.casefold()
        for group in configuration.address_groups
        if any(member.name.casefold() in fqdn_objects for member in group.members)
    }
    loopbacks = {
        interface.name.casefold()
        for interface in configuration.interfaces
        if interface.interface_type == "loopback"
    }
    vip_targets = {vip.name.casefold() for vip in configuration.vips} | {
        group.name.casefold() for group in configuration.vip_groups
    }
    matching = tuple(
        item
        for item in configuration.policies
        if any(
            address.relation == "source-address"
            and address.name.casefold() in fqdn_objects | source_groups
            for address in item.object_references
        )
        and any(interface.name.casefold() in loopbacks for interface in item.destination_interfaces)
        and any(
            address.relation == "destination-address" and address.name.casefold() in vip_targets
            for address in item.object_references
        )
    )
    passed = bool(matching)
    return _finding(
        control_id,
        title,
        AuditStatus.PASS if passed else AuditStatus.FAIL,
        "Une policy relie la source FQDN, une loopback et un VIP."
        if passed
        else "Aucune policy ne relie complètement la source FQDN, la loopback et le VIP.",
        tuple(f"policy conforme: {item.policy_id}" for item in matching)
        or ("chaîne d’accès absente",),
        tuple(
            EvidenceItem(section="firewall policy", entry=item.policy_id, directive="dstintf")
            for item in matching
        )
        or (EvidenceItem(section="firewall policy", directive="dstintf"),),
    )


def check_legacy_dns_database(
    configuration: FortiGateConfiguration,
    context: AuditContext | None = None,
) -> AuditFinding:
    control_id = "DNS-LEGACY-DATABASE-001"
    title = "Entrée DNS database historique"
    policy = _policy(context)
    section = configuration.document.section("system dns-database")
    if policy is None:
        return _unknown(
            control_id, title, "system dns-database", "Policy opérateur legacy_v1 absente."
        )
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return _unknown(
            control_id, title, "system dns-database", "Namespace DNS database absent ou ambigu."
        )
    if not _all_proven(configuration.dns_database_entries):
        return _unknown(
            control_id, title, "system dns-database", "Projection DNS database ambiguë."
        )
    matches = tuple(
        entry
        for entry in configuration.dns_database_entries
        if entry.name.casefold() == policy.dns_database_entry.casefold()
    )
    passed = bool(matches)
    return _finding(
        control_id,
        title,
        AuditStatus.PASS if passed else AuditStatus.FAIL,
        "L’entrée DNS database attendue est présente."
        if passed
        else "L’entrée DNS database attendue est absente.",
        ("cible DNS issue de la policy legacy_v1",),
        (
            EvidenceItem(
                section="system dns-database",
                entry=policy.dns_database_entry,
                directive="edit",
            ),
        ),
    )


check_legacy_local_admin.control_id = "IAM-LEGACY-ADMIN-001"
check_legacy_pki_removal.control_id = "IAM-LEGACY-PKI-REMOVAL-001"
check_legacy_pki_presence.control_id = "IAM-LEGACY-PKI-PRESENCE-001"
check_legacy_admin_loopback.control_id = "NET-LEGACY-ADMIN-LOOPBACK-001"
check_legacy_dns_database.control_id = "DNS-LEGACY-DATABASE-001"
