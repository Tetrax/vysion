from __future__ import annotations

from dataclasses import dataclass

from vysion.audit.models import (
    EvidenceCertainty,
    FortiGateConfiguration,
    IpsecPhase1,
    IpsecPhase2,
    ObjectReference,
    ProofState,
    SslVpnSettings,
    StructuralDirective,
    StructuralDocument,
    StructuralEntry,
    StructuralSection,
)

_SSL_KEYS = frozenset({"status", "source-interface", "source-address", "default-portal"})
_PHASE1_KEYS = frozenset({"status", "interface", "ike-version", "dhgrp", "proposal"})
_PHASE2_KEYS = frozenset({"status", "phase1name", "pfs", "dhgrp", "proposal"})


@dataclass(frozen=True)
class VpnProjection:
    ssl_vpn_settings: SslVpnSettings | None = None
    ipsec_phase1: tuple[IpsecPhase1, ...] = ()
    ipsec_phase2: tuple[IpsecPhase2, ...] = ()


def _directives(
    directives: tuple[StructuralDirective, ...],
    invalidated_keys: frozenset[str],
    allowed: frozenset[str],
) -> tuple[dict[str, StructuralDirective], frozenset[str]]:
    """Keep only one certain, non-mutating value for each projected key."""
    result: dict[str, StructuralDirective] = {}
    invalidated = set(invalidated_keys)
    for directive in directives:
        if directive.name not in allowed:
            continue
        if directive.name in invalidated:
            continue
        if directive.mutation or directive.certainty is not EvidenceCertainty.CERTAIN:
            invalidated.add(directive.name)
            result.pop(directive.name, None)
            continue
        if directive.name in result:
            invalidated.add(directive.name)
            result.pop(directive.name, None)
            continue
        result[directive.name] = directive
    return result, frozenset(invalidated)


def _single(
    values: dict[str, StructuralDirective],
    key: str,
    invalidated: set[str],
    *,
    casefold: bool = True,
) -> str | None:
    directive = values.get(key)
    if directive is None:
        return None
    if len(directive.tokens) != 1:
        invalidated.add(key)
        return None
    token = directive.tokens[0]
    return token.casefold() if casefold else token


def _tokens(
    values: dict[str, StructuralDirective],
    key: str,
    invalidated: set[str],
) -> tuple[str, ...]:
    directive = values.get(key)
    if directive is None:
        return ()
    if not directive.tokens:
        invalidated.add(key)
        return ()
    return tuple(token.casefold() for token in directive.tokens)


def _integers(
    values: dict[str, StructuralDirective],
    key: str,
    invalidated: set[str],
) -> tuple[int, ...]:
    tokens = _tokens(values, key, invalidated)
    if not tokens:
        return ()
    parsed: list[int] = []
    for token in tokens:
        try:
            parsed.append(int(token, 10))
        except ValueError:
            invalidated.add(key)
            return ()
    return tuple(parsed)


def _typed_keys(
    values: dict[str, StructuralDirective],
    invalidated: frozenset[str],
) -> frozenset[str]:
    return frozenset(set(values) - set(invalidated))


def _entry_proof(
    entry: StructuralEntry,
    invalidated: frozenset[str],
    required: frozenset[str],
) -> ProofState:
    if entry.certainty is not EvidenceCertainty.CERTAIN:
        return ProofState.UNKNOWN
    if invalidated or not required <= entry.parsed_keys:
        return ProofState.UNKNOWN
    return ProofState.PROVEN


def _section_proof(section: StructuralSection, invalidated: frozenset[str]) -> ProofState:
    if section.certainty is not EvidenceCertainty.CERTAIN or invalidated or not section.parsed_keys:
        return ProofState.UNKNOWN
    return ProofState.PROVEN


def _project_ssl(section: StructuralSection) -> SslVpnSettings:
    values, invalidated = _directives(section.directives, section.invalidated_keys, _SSL_KEYS)
    mutable_invalidated = set(invalidated)
    status = _single(values, "status", mutable_invalidated)
    source_interfaces = _tokens(values, "source-interface", mutable_invalidated)
    source_addresses = _tokens(values, "source-address", mutable_invalidated)
    default_portal = _single(values, "default-portal", mutable_invalidated)
    final_invalidated = frozenset(mutable_invalidated)
    return SslVpnSettings(
        status=status,
        source_interfaces=source_interfaces,
        source_addresses=source_addresses,
        default_portal=default_portal,
        parsed_keys=_typed_keys(values, final_invalidated),
        invalidated_keys=final_invalidated,
        proof_state=_section_proof(section, final_invalidated),
    )


def _project_phase1(entry: StructuralEntry) -> IpsecPhase1:
    values, invalidated = _directives(entry.directives, entry.invalidated_keys, _PHASE1_KEYS)
    mutable_invalidated = set(invalidated)
    status = _single(values, "status", mutable_invalidated)
    interface = _single(values, "interface", mutable_invalidated)
    ike_token = _single(values, "ike-version", mutable_invalidated)
    ike_version: int | None = None
    if ike_token is not None:
        try:
            ike_version = int(ike_token, 10)
        except ValueError:
            mutable_invalidated.add("ike-version")
    dh_groups = _integers(values, "dhgrp", mutable_invalidated)
    proposals = _tokens(values, "proposal", mutable_invalidated)
    final_invalidated = frozenset(mutable_invalidated)
    parsed_keys = _typed_keys(values, final_invalidated)
    return IpsecPhase1(
        name=entry.name,
        status=status,
        interface=interface,
        ike_version=ike_version,
        dh_groups=dh_groups,
        proposals=proposals,
        parsed_keys=parsed_keys,
        invalidated_keys=final_invalidated,
        proof_state=_entry_proof(
            entry,
            final_invalidated,
            frozenset({"interface", "ike-version", "dhgrp", "proposal"}),
        ),
    )


def _project_phase2(entry: StructuralEntry) -> IpsecPhase2:
    values, invalidated = _directives(entry.directives, entry.invalidated_keys, _PHASE2_KEYS)
    mutable_invalidated = set(invalidated)
    status = _single(values, "status", mutable_invalidated)
    phase1_name = _single(
        values,
        "phase1name",
        mutable_invalidated,
        casefold=False,
    )
    pfs = _single(values, "pfs", mutable_invalidated)
    dh_groups = _integers(values, "dhgrp", mutable_invalidated)
    proposals = _tokens(values, "proposal", mutable_invalidated)
    final_invalidated = frozenset(mutable_invalidated)
    parsed_keys = _typed_keys(values, final_invalidated)
    return IpsecPhase2(
        name=entry.name,
        status=status,
        phase1_name=phase1_name,
        phase1_reference=None,
        pfs=pfs,
        dh_groups=dh_groups,
        proposals=proposals,
        parsed_keys=parsed_keys,
        invalidated_keys=final_invalidated,
        proof_state=_entry_proof(
            entry,
            final_invalidated,
            frozenset({"phase1name", "dhgrp", "proposal"}),
        ),
    )


def project_vpn(document: StructuralDocument) -> VpnProjection:
    ssl: SslVpnSettings | None = None
    phase1: list[IpsecPhase1] = []
    phase2: list[IpsecPhase2] = []

    for section in document.sections:
        if section.name == "vpn ssl settings":
            ssl = _project_ssl(section)
        elif section.name == "vpn ipsec phase1-interface":
            phase1.extend(_project_phase1(entry) for entry in section.entries)
        elif section.name == "vpn ipsec phase2-interface":
            phase2.extend(_project_phase2(entry) for entry in section.entries)

    phase1_by_name: dict[str, list[IpsecPhase1]] = {}
    for item in phase1:
        if item.proof_state is ProofState.PROVEN:
            phase1_by_name.setdefault(item.name, []).append(item)

    resolved_phase2: list[IpsecPhase2] = []
    for item in phase2:
        matches = phase1_by_name.get(item.phase1_name or "", [])
        if len(matches) == 1:
            reference = ObjectReference(
                object_type="ipsec-phase1",
                name=matches[0].name,
                relation="phase2-phase1",
            )
            item = item.model_copy(
                update={
                    "phase1_reference": reference,
                    "proof_state": (
                        ProofState.PROVEN
                        if item.proof_state is ProofState.PROVEN
                        else ProofState.UNKNOWN
                    ),
                }
            )
        else:
            item = item.model_copy(
                update={"phase1_reference": None, "proof_state": ProofState.UNKNOWN}
            )
        resolved_phase2.append(item)

    return VpnProjection(
        ssl_vpn_settings=ssl,
        ipsec_phase1=tuple(phase1),
        ipsec_phase2=tuple(resolved_phase2),
    )


def apply_vpn_projection(
    configuration: FortiGateConfiguration,
    projection: VpnProjection,
) -> FortiGateConfiguration:
    return configuration.model_copy(
        update={
            "ssl_vpn_settings": projection.ssl_vpn_settings,
            "ipsec_phase1": projection.ipsec_phase1,
            "ipsec_phase2": projection.ipsec_phase2,
        }
    )
