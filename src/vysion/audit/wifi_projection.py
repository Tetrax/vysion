from dataclasses import dataclass

from vysion.audit.models import (
    EvidenceCertainty,
    FortiGateConfiguration,
    ObjectReference,
    ProofState,
    StructuralEntry,
    StructuralSection,
    WirelessAccessPoint,
    WirelessProfile,
    WirelessRadio,
)


@dataclass(frozen=True)
class WifiProjection:
    access_points: tuple[WirelessAccessPoint, ...] = ()
    profiles: tuple[WirelessProfile, ...] = ()


def _values(entry: StructuralEntry, allowed: frozenset[str]):
    values = {}
    invalid = set(entry.invalidated_keys)
    for directive in entry.directives:
        if directive.name not in allowed or directive.name in invalid:
            continue
        if (
            directive.mutation
            or directive.certainty is not EvidenceCertainty.CERTAIN
            or directive.name in values
        ):
            invalid.add(directive.name)
            values.pop(directive.name, None)
        else:
            values[directive.name] = directive.tokens
    return values, invalid


def _radio(section: StructuralSection) -> WirelessRadio:
    entry = StructuralEntry(
        name=section.name,
        line=section.line,
        directives=section.directives,
        parsed_keys=section.parsed_keys,
        invalidated_keys=section.invalidated_keys,
        certainty=section.certainty,
    )
    values, invalid = _values(
        entry,
        frozenset(
            {"mode", "vaps", "channel-bonding", "darrp", "band", "channel", "short-guard-interval"}
        ),
    )
    return WirelessRadio(
        name=section.name,
        mode=values.get("mode", (None,))[0],
        vaps=values.get("vaps", ()),
        channel_bonding=values.get("channel-bonding", (None,))[0],
        darrp=values.get("darrp", (None,))[0],
        band=values.get("band", (None,))[0],
        channels=values.get("channel", ()),
        short_guard_interval=values.get("short-guard-interval", (None,))[0],
        parsed_keys=frozenset(values),
        proof_state=ProofState.PROVEN
        if section.certainty is EvidenceCertainty.CERTAIN and not invalid
        else ProofState.UNKNOWN,
    )


def project_wifi(document) -> WifiProjection:
    access_points = []
    profiles = []
    for section in document.sections:
        if section.name == "wireless-controller wtp":
            for entry in section.entries:
                values, invalid = _values(entry, frozenset({"name", "wtp-profile"}))
                profile_tokens = values.get("wtp-profile", ())
                access_points.append(
                    WirelessAccessPoint(
                        device_id=entry.name,
                        name=values.get("name", (None,))[0],
                        profile=ObjectReference(
                            object_type="wireless-profile",
                            name=profile_tokens[0],
                            relation="wtp-profile",
                        )
                        if len(profile_tokens) == 1
                        else None,
                        parsed_keys=frozenset(values),
                        proof_state=ProofState.PROVEN
                        if section.certainty is EvidenceCertainty.CERTAIN
                        and entry.certainty is EvidenceCertainty.CERTAIN
                        and not invalid
                        and len(profile_tokens) == 1
                        else ProofState.UNKNOWN,
                    )
                )
        elif section.name == "wireless-controller wtp-profile":
            for entry in section.entries:
                values, invalid = _values(
                    entry, frozenset({"frequency-handoff", "powersave-optimize"})
                )
                radios = tuple(
                    _radio(child)
                    for child in entry.children
                    if child.name in {"radio-1", "radio-2"}
                )
                profiles.append(
                    WirelessProfile(
                        name=entry.name,
                        frequency_handoff=values.get("frequency-handoff", (None,))[0],
                        powersave_optimize=values.get("powersave-optimize", ()),
                        radios=radios,
                        parsed_keys=frozenset(values),
                        proof_state=ProofState.PROVEN
                        if section.certainty is EvidenceCertainty.CERTAIN
                        and entry.certainty is EvidenceCertainty.CERTAIN
                        and not invalid
                        and all(r.proof_state is ProofState.PROVEN for r in radios)
                        else ProofState.UNKNOWN,
                    )
                )
    return WifiProjection(tuple(access_points), tuple(profiles))


def apply_wifi_projection(
    configuration: FortiGateConfiguration, projection: WifiProjection
) -> FortiGateConfiguration:
    return configuration.model_copy(
        update={
            "wireless_access_points": projection.access_points,
            "wireless_profiles": projection.profiles,
        }
    )
