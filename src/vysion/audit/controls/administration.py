from __future__ import annotations

from collections.abc import Iterable

from vysion.audit.controls._evidence import (
    evidence_for_complete_backup,
    evidence_for_directive,
    evidence_for_entry,
    evidence_for_section,
)
from vysion.audit.models import (
    AffectedObject,
    Applicability,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    EvidenceItem,
    FortiGateConfiguration,
    ObjectReference,
    RiskAssessment,
    StructuralDirective,
    StructuralEntry,
)

_DISABLED_MFA = {"", "disable", "none"}
_SUPPORTED_MFA = {"fortitoken", "email", "sms"}


def _risk(summary: str, impact: str, likelihood: str, treatment: str) -> RiskAssessment:
    return RiskAssessment(
        summary=summary,
        impact=impact,
        likelihood=likelihood,
        treatment=treatment,
    )


def _affected(names: Iterable[str], object_type: str) -> tuple[AffectedObject, ...]:
    return tuple(
        AffectedObject(
            name=name,
            object_type=object_type,
            reference=ObjectReference(object_type=object_type, name=name),
        )
        for name in names
    )


def _directives(entry: StructuralEntry, name: str) -> tuple[StructuralDirective, ...]:
    return tuple(directive for directive in entry.directives if directive.name == name)


def _certain(entry: StructuralEntry, name: str) -> StructuralDirective | None:
    if entry.certainty is not EvidenceCertainty.CERTAIN or name in entry.invalidated_keys:
        return None
    directives = tuple(
        directive
        for directive in _directives(entry, name)
        if not directive.mutation and directive.certainty is EvidenceCertainty.CERTAIN
    )
    return directives[0] if len(directives) == 1 else None


def _values(entry: StructuralEntry, name: str) -> tuple[str, ...]:
    if name in entry.invalidated_keys:
        return ()
    return tuple(
        token.casefold()
        for directive in _directives(entry, name)
        if not directive.mutation and directive.certainty is EvidenceCertainty.CERTAIN
        for token in directive.tokens
    )


def _items(
    configuration: FortiGateConfiguration,
    section: str,
    directive: str,
    entries: Iterable[str] = (),
    certainty: EvidenceCertainty | None = None,
) -> tuple[EvidenceItem, ...]:
    names = tuple(entries)
    if not names:
        return (
            evidence_for_directive(
                configuration.document,
                section,
                directive,
                certainty=certainty,
            ),
        )
    return tuple(
        evidence_for_directive(
            configuration.document,
            section,
            directive,
            entry_name=name,
            certainty=certainty,
        )
        for name in names
    )


def _finding(
    *,
    configuration: FortiGateConfiguration,
    control_id: str,
    title: str,
    status: AuditStatus,
    applicability: Applicability,
    evidence: tuple[str, ...],
    section: str,
    directive: str,
    entries: Iterable[str] = (),
    evidence_items: tuple[EvidenceItem, ...] | None = None,
    object_type: str = "account",
    certainty: EvidenceCertainty | None = None,
    message: str,
    risk: RiskAssessment,
    recommendation: str,
    remediation: str,
) -> AuditFinding:
    names = tuple(entries)
    return AuditFinding(
        control_id=control_id,
        title=title,
        category="identity",
        priority=AuditPriority.P0,
        severity=AuditSeverity.HIGH,
        status=status,
        applicability=applicability,
        evidence=evidence,
        evidence_items=evidence_items
        or _items(configuration, section, directive, names, certainty),
        affected_objects=_affected(names, object_type),
        message=message,
        risk=risk,
        recommendation=recommendation,
        remediation=remediation,
    )


def _admin_unknown(
    configuration: FortiGateConfiguration,
    evidence: tuple[str, ...],
    entries: Iterable[StructuralEntry] = (),
) -> AuditFinding:
    names = tuple(entry.name for entry in entries)
    return _finding(
        configuration=configuration,
        control_id="IAM-ADMIN-MFA-001",
        title="MFA des administrateurs",
        status=AuditStatus.UNKNOWN,
        applicability=Applicability.UNKNOWN,
        evidence=evidence,
        section="system admin",
        directive="two-factor",
        entries=names,
        certainty=EvidenceCertainty.AMBIGUOUS,
        message="La présence d'un MFA ne peut pas être prouvée pour tous les administrateurs.",
        risk=_risk(
            "L'état MFA des administrateurs ne peut pas être déterminé.",
            "Un compte administrateur pourrait rester sans second facteur.",
            "indéterminée",
            "Obtenir une section system admin complète et chaque directive MFA.",
        ),
        recommendation="Fournir two-factor et peer-auth pour chaque administrateur.",
        remediation="Compléter l'export puis relancer l'audit avant de conclure.",
    )


def check_admin_mfa(configuration: FortiGateConfiguration) -> AuditFinding:
    section = configuration.document.section("system admin")
    if section is None:
        return _admin_unknown(configuration, ("system admin: namespace absent",))
    # An empty admin namespace is not proof that the export is complete enough
    # to establish MFA coverage; default-account absence is a separate control.
    if not section.entries:
        return _admin_unknown(configuration, ("system admin: section vide",))

    failures: list[StructuralEntry] = []
    unknown: list[StructuralEntry] = []
    compliant: list[StructuralEntry] = []
    exempt: list[StructuralEntry] = []
    for entry in section.entries:
        # Explicit failure remains FAIL even when a later mutation or conflict
        # makes the rest of the entry uncertain.
        if any(value in _DISABLED_MFA for value in _values(entry, "two-factor")):
            failures.append(entry)
            continue
        peer_auth = _certain(entry, "peer-auth")
        if peer_auth is not None and tuple(token.casefold() for token in peer_auth.tokens) == (
            "enable",
        ):
            exempt.append(entry)
            continue
        two_factor = _certain(entry, "two-factor")
        if two_factor is None or len(two_factor.tokens) != 1:
            unknown.append(entry)
        elif two_factor.tokens[0].casefold() in _SUPPORTED_MFA:
            compliant.append(entry)
        else:
            unknown.append(entry)

    if failures:
        return _finding(
            configuration=configuration,
            control_id="IAM-ADMIN-MFA-001",
            title="MFA des administrateurs",
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"administrateur sans MFA: {entry.name}" for entry in failures),
            section="system admin",
            directive="two-factor",
            entries=(entry.name for entry in failures),
            message="MFA absent ou explicitement désactivé pour au moins un administrateur.",
            risk=_risk(
                "Un ou plusieurs comptes administrateurs n'ont pas de MFA effectif.",
                "Compromission facilitée d'un compte administrateur.",
                "élevée",
                "Activer une méthode MFA supportée et tester une connexion contrôlée.",
            ),
            recommendation=(
                "Activer une méthode MFA supportée pour chaque administrateur applicable."
            ),
            remediation="Configurer FortiToken, email ou SMS puis valider chaque compte.",
        )
    if unknown or section.certainty is not EvidenceCertainty.CERTAIN:
        unknown_entries = tuple(unknown) or tuple(section.entries)
        return _admin_unknown(
            configuration,
            tuple(f"directive MFA absente ou ambiguë: {entry.name}" for entry in unknown_entries),
            unknown_entries,
        )

    if not compliant:
        return _finding(
            configuration=configuration,
            control_id="IAM-ADMIN-MFA-001",
            title="MFA des administrateurs",
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=tuple(
                f"administrateur exempté par peer-auth: {entry.name}" for entry in exempt
            ),
            section="system admin",
            directive="peer-auth",
            entries=(entry.name for entry in exempt),
            message="Tous les administrateurs sont couverts par peer-auth explicitement activé.",
            risk=_risk(
                "Aucun administrateur n'est applicable au MFA local par mot de passe.",
                "La sécurité dépend de l'authentification homologue configurée.",
                "faible",
                "Conserver peer-auth et sa preuve de fonctionnement.",
            ),
            recommendation="Maintenir l'authentification homologue explicitement activée.",
            remediation="Aucune remédiation MFA immédiate; revoir peer-auth lors des changements.",
        )
    return _finding(
        configuration=configuration,
        control_id="IAM-ADMIN-MFA-001",
        title="MFA des administrateurs",
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(f"administrateur conforme: {entry.name}" for entry in compliant + exempt),
        section="system admin",
        directive="two-factor",
        entries=(entry.name for entry in compliant),
        message="Tous les administrateurs applicables utilisent un MFA supporté.",
        risk=_risk(
            "Un MFA supporté est probant pour tous les administrateurs applicables.",
            "La compromission par mot de passe seul est réduite.",
            "faible",
            "Conserver le MFA et surveiller les changements de comptes.",
        ),
        recommendation="Conserver une méthode MFA supportée pour chaque administrateur applicable.",
        remediation="Aucune remédiation immédiate; contrôler les nouveaux comptes.",
    )


def check_local_user_mfa(configuration: FortiGateConfiguration) -> AuditFinding:
    section = configuration.document.section("user local")
    if section is None:
        if configuration.complete_backup:
            return _finding(
                configuration=configuration,
                control_id="IAM-LOCAL-USER-MFA-001",
                title="MFA des utilisateurs locaux",
                status=AuditStatus.PASS,
                applicability=Applicability.NOT_APPLICABLE,
                evidence=("backup complet: namespace user local absent",),
                section="user local",
                directive="two-factor",
                evidence_items=(evidence_for_complete_backup(),),
                object_type="local-user",
                message="Aucun utilisateur local n'est déclaré dans le backup complet.",
                risk=_risk(
                    "Aucun compte local n'est présent dans le backup complet.",
                    "Le contrôle MFA local n'est pas applicable.",
                    "faible",
                    "Surveiller toute création ultérieure de compte local.",
                ),
                recommendation="Conserver l'absence de comptes locaux si elle est attendue.",
                remediation="Aucune remédiation immédiate.",
            )
        return _finding(
            configuration=configuration,
            control_id="IAM-LOCAL-USER-MFA-001",
            title="MFA des utilisateurs locaux",
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("user local: namespace absent",),
            section="user local",
            directive="two-factor",
            certainty=EvidenceCertainty.INVALID,
            object_type="local-user",
            message="Le namespace des utilisateurs locaux est absent.",
            risk=_risk(
                "La présence d'utilisateurs locaux ne peut pas être déterminée.",
                "Un compte local sans MFA pourrait rester non détecté.",
                "indéterminée",
                "Obtenir une exportation complète du namespace user local.",
            ),
            recommendation="Fournir la section user local complète.",
            remediation="Rejouer l'export avec tous les utilisateurs locaux et leur MFA.",
        )

    failures = tuple(
        entry
        for entry in section.entries
        if any(value in _DISABLED_MFA for value in _values(entry, "two-factor"))
    )
    if failures:
        return _finding(
            configuration=configuration,
            control_id="IAM-LOCAL-USER-MFA-001",
            title="MFA des utilisateurs locaux",
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(f"utilisateur local sans MFA: {entry.name}" for entry in failures),
            section="user local",
            directive="two-factor",
            entries=(entry.name for entry in failures),
            object_type="local-user",
            message="MFA absent ou explicitement désactivé pour au moins un utilisateur local.",
            risk=_risk(
                "Un ou plusieurs utilisateurs locaux n'ont pas de MFA effectif.",
                "Une compromission par mot de passe seul est facilitée.",
                "élevée",
                "Activer une méthode MFA supportée pour chaque utilisateur local.",
            ),
            recommendation="Activer le MFA pour chaque utilisateur local.",
            remediation="Configurer une méthode MFA supportée puis tester chaque compte.",
        )
    if section.certainty is not EvidenceCertainty.CERTAIN:
        return _finding(
            configuration=configuration,
            control_id="IAM-LOCAL-USER-MFA-001",
            title="MFA des utilisateurs locaux",
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=("user local: section ambiguë ou conflictuelle",),
            section="user local",
            directive="two-factor",
            entries=(entry.name for entry in section.entries),
            certainty=EvidenceCertainty.AMBIGUOUS,
            object_type="local-user",
            message="La liste des utilisateurs locaux ou leurs directives est ambiguë.",
            risk=_risk(
                "La présence d'un MFA ne peut pas être prouvée pour tous les comptes locaux.",
                "Un compte local peut rester non audité.",
                "indéterminée",
                "Corriger les conflits puis fournir une section complète.",
            ),
            recommendation="Fournir une section user local certaine et exhaustive.",
            remediation="Corriger les doublons ou mutations puis relancer l'audit.",
        )
    if not section.entries:
        return _finding(
            configuration=configuration,
            control_id="IAM-LOCAL-USER-MFA-001",
            title="MFA des utilisateurs locaux",
            status=AuditStatus.PASS,
            applicability=Applicability.NOT_APPLICABLE,
            evidence=("user local: section explicitement vide",),
            section="user local",
            directive="two-factor",
            object_type="local-user",
            message="Aucun utilisateur local n'est déclaré.",
            risk=_risk(
                "Aucun compte local n'est présent dans le namespace audité.",
                "Le contrôle MFA local n'est pas applicable à ce namespace vide.",
                "faible",
                "Surveiller toute création ultérieure de compte local.",
            ),
            recommendation="Conserver le namespace local vide si cela est attendu.",
            remediation="Aucune remédiation immédiate; réévaluer après création d'un compte.",
        )

    compliant: list[StructuralEntry] = []
    unknown: list[StructuralEntry] = []
    for entry in section.entries:
        two_factor = _certain(entry, "two-factor")
        if two_factor is None or len(two_factor.tokens) != 1:
            unknown.append(entry)
        elif two_factor.tokens[0].casefold() in _SUPPORTED_MFA:
            compliant.append(entry)
        else:
            unknown.append(entry)
    if unknown:
        return _finding(
            configuration=configuration,
            control_id="IAM-LOCAL-USER-MFA-001",
            title="MFA des utilisateurs locaux",
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=tuple(f"directive MFA absente ou ambiguë: {entry.name}" for entry in unknown),
            section="user local",
            directive="two-factor",
            entries=(entry.name for entry in unknown),
            certainty=EvidenceCertainty.AMBIGUOUS,
            object_type="local-user",
            message=(
                "La présence d'un MFA ne peut pas être prouvée pour tous "
                "les utilisateurs locaux."
            ),
            risk=_risk(
                "La présence d'un MFA ne peut pas être prouvée pour tous les utilisateurs locaux.",
                "Un compte local sans MFA peut être présent malgré un export incomplet.",
                "indéterminée",
                "Obtenir la directive two-factor pour chaque utilisateur local.",
            ),
            recommendation="Fournir la directive two-factor de chaque utilisateur local.",
            remediation="Compléter l'export puis relancer l'audit avant de conclure.",
        )
    return _finding(
        configuration=configuration,
        control_id="IAM-LOCAL-USER-MFA-001",
        title="MFA des utilisateurs locaux",
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=tuple(f"utilisateur local conforme: {entry.name}" for entry in compliant),
        section="user local",
        directive="two-factor",
        entries=(entry.name for entry in compliant),
        object_type="local-user",
        message="Tous les utilisateurs locaux déclarés utilisent une méthode MFA supportée.",
        risk=_risk(
            "Un MFA supporté est probant pour tous les utilisateurs locaux déclarés.",
            "La compromission par mot de passe seul est réduite.",
            "faible",
            "Conserver le MFA et surveiller les changements de comptes.",
        ),
        recommendation="Conserver une méthode MFA supportée pour chaque utilisateur local.",
        remediation="Aucune remédiation immédiate; contrôler les nouveaux comptes.",
    )


def _absence_finding(
    configuration: FortiGateConfiguration,
    *,
    control_id: str,
    title: str,
    target: str,
    namespaces: tuple[str, ...],
) -> AuditFinding:
    sections = tuple(configuration.document.section(namespace) for namespace in namespaces)
    found: list[tuple[str, StructuralEntry]] = []
    incomplete = False
    for namespace, section in zip(namespaces, sections, strict=True):
        if section is None:
            incomplete = incomplete or not configuration.complete_backup
            continue
        for entry in section.entries:
            if entry.name.casefold() == target.casefold():
                found.append((namespace, entry))
            elif entry.certainty is not EvidenceCertainty.CERTAIN:
                incomplete = True
        if section.certainty is not EvidenceCertainty.CERTAIN:
            incomplete = True
    object_type = "administrator" if target == "admin" else "account"
    if found:
        items = tuple(
            evidence_for_entry(
                configuration.document,
                namespace,
                entry.name,
                certainty=EvidenceCertainty.CERTAIN,
            )
            for namespace, entry in found
        )
        return _finding(
            configuration=configuration,
            control_id=control_id,
            title=title,
            status=AuditStatus.FAIL,
            applicability=Applicability.APPLICABLE,
            evidence=tuple(
                f"compte {target} présent dans {namespace}: {entry.name}"
                for namespace, entry in found
            ),
            section=found[0][0],
            directive="account",
            entries=(entry.name for _, entry in found),
            evidence_items=items,
            object_type=object_type,
            message=f"Le compte par défaut {target} est présent.",
            risk=_risk(
                f"Le compte par défaut {target} reste disponible.",
                "Un identifiant connu facilite les tentatives de compromission.",
                "élevée",
                f"Supprimer ou renommer le compte {target} selon la procédure client.",
            ),
            recommendation=f"Supprimer le compte par défaut {target}.",
            remediation=(
                f"Retirer {target} des namespaces concernés puis valider l'accès de secours."
            ),
        )
    if incomplete:
        incomplete_items = tuple(
            evidence_for_section(
                configuration.document,
                namespace,
                certainty=EvidenceCertainty.AMBIGUOUS,
            )
            for namespace, section in zip(namespaces, sections, strict=True)
            if section is None or section.certainty is not EvidenceCertainty.CERTAIN
        )
        return _finding(
            configuration=configuration,
            control_id=control_id,
            title=title,
            status=AuditStatus.UNKNOWN,
            applicability=Applicability.UNKNOWN,
            evidence=(f"preuve d'absence incomplète pour {target}",),
            section=namespaces[0],
            directive="account",
            evidence_items=incomplete_items
            or (evidence_for_section(configuration.document, namespaces[0]),),
            object_type=object_type,
            message=f"L'absence du compte par défaut {target} ne peut pas être prouvée.",
            risk=_risk(
                f"La présence éventuelle du compte {target} reste indéterminée.",
                "Un compte connu pourrait rester exploitable.",
                "indéterminée",
                "Fournir les namespaces complets et exhaustifs.",
            ),
            recommendation="Fournir les sections de comptes complètes et certaines.",
            remediation="Compléter l'export puis relancer l'audit avant de conclure.",
        )
    return _finding(
        configuration=configuration,
        control_id=control_id,
        title=title,
        status=AuditStatus.PASS,
        applicability=Applicability.APPLICABLE,
        evidence=(f"compte {target} absent des namespaces certains",),
        section=namespaces[0],
        directive="account",
        evidence_items=tuple(
            evidence_for_section(configuration.document, namespace)
            for namespace in namespaces
            if configuration.document.section(namespace) is not None
        )
        + (
            (evidence_for_complete_backup(),)
            if any(configuration.document.section(namespace) is None for namespace in namespaces)
            else ()
        ),
        object_type=object_type,
        message=f"Le compte par défaut {target} est absent des sections contrôlées.",
        risk=_risk(
            f"L'absence de {target} est probante dans les namespaces exportés.",
            "Les tentatives ciblant ce compte connu sont réduites.",
            "faible",
            "Surveiller la réapparition du compte lors des changements.",
        ),
        recommendation=f"Conserver le compte {target} absent et surveiller les créations.",
        remediation="Aucune remédiation immédiate.",
    )


def check_default_admin(configuration: FortiGateConfiguration) -> AuditFinding:
    return _absence_finding(
        configuration,
        control_id="IAM-DEFAULT-ADMIN-001",
        title="Absence du compte administrateur par défaut",
        target="admin",
        namespaces=("system admin",),
    )


def check_guest_account(configuration: FortiGateConfiguration) -> AuditFinding:
    return _absence_finding(
        configuration,
        control_id="IAM-GUEST-ACCOUNT-001",
        title="Absence du compte guest",
        target="guest",
        namespaces=("user local",),
    )
