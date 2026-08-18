import re
from collections.abc import Callable

from vysion.audit.models import (
    Applicability,
    AuditFinding,
    AuditPriority,
    AuditSeverity,
    AuditStatus,
    EvidenceCertainty,
    EvidenceItem,
    FortiGateConfiguration,
    ProofState,
    RiskAssessment,
    WirelessProfile,
)

_PROVENANCE = "legacy_v1"
_ALLOWED_BANDS = {
    "802.11n-only",
    "802.11ac-only",
    "802.11ac,n-only",
    "802.11ax-only",
    "802.11ax,n-only",
}


def _finding(
    control_id: str, title: str, status: AuditStatus, details: tuple[str, ...]
) -> AuditFinding:
    return AuditFinding(
        control_id=control_id,
        title=title,
        status=status,
        category="wifi",
        priority=AuditPriority.P1,
        severity=AuditSeverity.MEDIUM,
        applicability=Applicability.NOT_APPLICABLE
        if status is AuditStatus.NOT_APPLICABLE
        else Applicability.UNKNOWN
        if status is AuditStatus.UNKNOWN
        else Applicability.APPLICABLE,
        evidence=details + ("provenance: legacy_v1",),
        evidence_items=(
            EvidenceItem(
                section="wireless-controller wtp-profile",
                directive="legacy-proof",
                tokens=details,
                certainty=EvidenceCertainty.AMBIGUOUS
                if status is AuditStatus.UNKNOWN
                else EvidenceCertainty.CERTAIN,
            ),
        ),
        message=details[0],
        risk=RiskAssessment(
            summary="Le réglage Wi-Fi historique V1 n’est pas respecté.",
            impact="La sécurité ou la qualité radio peut être dégradée.",
            likelihood="indéterminée" if status is AuditStatus.UNKNOWN else "moyenne",
            treatment="Aligner le profil utilisé sur la règle legacy_v1.",
        ),
        recommendation="Corriger les profils FortiAP réellement référencés.",
        remediation="Modifier le profil WTP puis rejouer l’audit.",
        rule_provenance=_PROVENANCE,
    )


def _scope(configuration: FortiGateConfiguration):
    wtp = configuration.document.section("wireless-controller wtp")
    profiles_section = configuration.document.section("wireless-controller wtp-profile")
    if wtp is None:
        return (
            (AuditStatus.NOT_APPLICABLE if configuration.complete_backup else AuditStatus.UNKNOWN),
            (),
            "Namespace WTP absent.",
        )
    if wtp.certainty is not EvidenceCertainty.CERTAIN:
        return AuditStatus.UNKNOWN, (), "Namespace WTP ambigu."
    if not configuration.wireless_access_points:
        return AuditStatus.NOT_APPLICABLE, (), "Namespace WTP certainement vide."
    if profiles_section is None or profiles_section.certainty is not EvidenceCertainty.CERTAIN:
        return AuditStatus.UNKNOWN, (), "Namespace profils WTP absent ou ambigu."
    aps = configuration.wireless_access_points
    profiles = configuration.wireless_profiles
    profile_map = {p.name.casefold(): p for p in profiles}
    refs = [ap.profile.name.casefold() for ap in aps if ap.profile is not None]
    if (
        any(ap.proof_state is not ProofState.PROVEN for ap in aps)
        or any(p.proof_state is not ProofState.PROVEN for p in profiles)
        or len(profile_map) != len(profiles)
        or len(refs) != len(aps)
        or any(ref not in profile_map for ref in refs)
    ):
        return AuditStatus.UNKNOWN, (), "WTP/profil muté, en collision ou référence manquante."
    return None, tuple(profile_map[ref] for ref in dict.fromkeys(refs)), ""


def _profile_control(
    configuration, control_id, title, violation: Callable[[WirelessProfile], bool]
):
    profile_map = {profile.name.casefold(): profile for profile in configuration.wireless_profiles}
    referenced = tuple(
        profile_map[access_point.profile.name.casefold()]
        for access_point in configuration.wireless_access_points
        if access_point.profile is not None and access_point.profile.name.casefold() in profile_map
    )
    certain_failures = tuple(
        profile.name
        for profile in dict.fromkeys(referenced)
        if profile.proof_state is ProofState.PROVEN and violation(profile)
    )
    if certain_failures:
        return _finding(
            control_id,
            title,
            AuditStatus.FAIL,
            ("Profils non conformes: " + ", ".join(certain_failures),),
        )
    state, profiles, reason = _scope(configuration)
    if state is not None:
        return _finding(control_id, title, state, (reason,))
    failed = tuple(profile.name for profile in profiles if violation(profile))
    return _finding(
        control_id,
        title,
        AuditStatus.FAIL if failed else AuditStatus.PASS,
        (
            ("Profils non conformes: " + ", ".join(failed))
            if failed
            else "Tous les profils utilisés sont conformes.",
        ),
    )


def _radio(profile, name):
    return next((r for r in profile.radios if r.name == name), None)


def check_obsolete_fortiap(configuration):
    obsolete = []
    for ap in configuration.wireless_access_points:
        identifier = ap.device_id.upper()
        model = None
        if identifier.startswith("FAP"):
            rest = identifier[3:]
            match = re.match(r"^(\d{2})B", rest)
            model = f"{match.group(1)}0B" if match else None
            if model is None and (match := re.match(r"^(\d{3})B", rest)):
                model = f"{match.group(1)}B"
            if model is None and (match := re.match(r"(\d{2,3}[A-Z])", rest)):
                model = match.group(1)
        elif identifier.startswith("FP"):
            model = identifier[2:6]
        if model and model.endswith(("B", "C")):
            obsolete.append(ap.device_id)
    if obsolete:
        return _finding(
            "WIFI-FORTIAP-OBSOLETE-001",
            "Modèles FortiAP obsolètes",
            AuditStatus.FAIL,
            ("Bornes obsolètes: " + ", ".join(obsolete),),
        )
    state, _, reason = _scope(configuration)
    if state is not None:
        return _finding(
            "WIFI-FORTIAP-OBSOLETE-001",
            "Modèles FortiAP obsolètes",
            state,
            (reason,),
        )
    return _finding(
        "WIFI-FORTIAP-OBSOLETE-001",
        "Modèles FortiAP obsolètes",
        AuditStatus.FAIL if obsolete else AuditStatus.PASS,
        (
            ("Bornes obsolètes: " + ", ".join(obsolete))
            if obsolete
            else "Aucun suffixe B/C obsolète détecté.",
        ),
    )


def check_ssid_limit(c):
    return _profile_control(
        c,
        "WIFI-SSID-LIMIT-001",
        "Nombre de SSID par radio",
        lambda p: any(len(r.vaps) >= 5 for r in p.radios),
    )


def check_radio2_40mhz(c):
    return _profile_control(
        c,
        "WIFI-RADIO2-40MHZ-001",
        "Radio 2 et largeur 40 MHz",
        lambda p: (r := _radio(p, "radio-2")) is None
        or r.mode == "disabled"
        or r.channel_bonding != "40MHz",
    )


def check_darrp(c):
    return _profile_control(
        c,
        "WIFI-DARRP-001",
        "DARRP sur les radios actives",
        lambda p: any(
            (r := _radio(p, n)) is None or (r.mode != "disabled" and r.darrp != "enable")
            for n in ("radio-1", "radio-2")
        ),
    )


def check_frequency_handoff(c):
    return _profile_control(
        c,
        "WIFI-FREQUENCY-HANDOFF-001",
        "Frequency handoff",
        lambda p: (r := _radio(p, "radio-1")) is None
        or (r.mode != "disabled" and p.frequency_handoff != "enable"),
    )


def check_tim(c):
    return _profile_control(
        c,
        "WIFI-TIM-001",
        "TIM powersave",
        lambda p: any(
            (r := _radio(p, n)) is None
            or (r.mode != "disabled" and "tim" not in p.powersave_optimize)
            for n in ("radio-1", "radio-2")
        ),
    )


def check_band(c):
    return _profile_control(
        c,
        "WIFI-BAND-001",
        "Bandes Wi-Fi autorisées",
        lambda p: any(
            (r := _radio(p, n)) is None or (r.mode != "disabled" and r.band not in _ALLOWED_BANDS)
            for n in ("radio-1", "radio-2")
        ),
    )


def check_channels(c):
    return _profile_control(
        c,
        "WIFI-CHANNELS-001",
        "Canaux radio 1",
        lambda p: (r := _radio(p, "radio-1")) is None
        or (
            r.mode != "disabled"
            and not (set(r.channels) == {"1", "6", "11"} and len(r.channels) == 3)
        ),
    )


def check_short_guard_interval(c):
    return _profile_control(
        c,
        "WIFI-SHORT-GUARD-INTERVAL-001",
        "Short guard interval",
        lambda p: any(
            (r := _radio(p, n)) is None
            or (r.mode != "disabled" and r.short_guard_interval != "enable")
            for n in ("radio-1", "radio-2")
        ),
    )


for _control, _id in (
    (check_obsolete_fortiap, "WIFI-FORTIAP-OBSOLETE-001"),
    (check_ssid_limit, "WIFI-SSID-LIMIT-001"),
    (check_radio2_40mhz, "WIFI-RADIO2-40MHZ-001"),
    (check_darrp, "WIFI-DARRP-001"),
    (check_frequency_handoff, "WIFI-FREQUENCY-HANDOFF-001"),
    (check_tim, "WIFI-TIM-001"),
    (check_band, "WIFI-BAND-001"),
    (check_channels, "WIFI-CHANNELS-001"),
    (check_short_guard_interval, "WIFI-SHORT-GUARD-INTERVAL-001"),
):
    _control.control_id = _id
