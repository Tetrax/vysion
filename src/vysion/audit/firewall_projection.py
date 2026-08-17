from __future__ import annotations

import re
from dataclasses import dataclass

from vysion.audit.models import (
    EvidenceCertainty,
    FortiGateConfiguration,
    LogSetting,
    ObjectReference,
    Policy,
    PortRange,
    ProfileGroup,
    ProofState,
    RealServer,
    SecurityProfile,
    ServiceObject,
    StructuralDirective,
    StructuralDocument,
    StructuralEntry,
    StructuralSection,
    Vip,
    VipGroup,
    VirtualServer,
)

_POLICY_KEYS = frozenset(
    {
        "name",
        "srcintf",
        "dstintf",
        "srcaddr",
        "dstaddr",
        "action",
        "status",
        "schedule",
        "service",
        "logtraffic",
        "utm-status",
        "profile-group",
        "webfilter-profile",
        "ips-sensor",
        "av-profile",
        "dnsfilter-profile",
        "application-list",
        "ssl-ssh-profile",
        "voip-profile",
        "waf-profile",
        "virtual-patch-profile",
        "file-filter-profile",
        "icap-profile",
        "internet-service",
        "internet-service-name",
    }
)
_SERVICE_KEYS = frozenset(
    {"tcp-portrange", "udp-portrange", "member", "protocol", "protocol-number"}
)
_VIP_KEYS = frozenset({"extintf", "extip", "mappedip", "type"})
_PROFILE_GROUP_KEYS = frozenset(
    {
        "webfilter-profile",
        "ips-sensor",
        "av-profile",
        "dnsfilter-profile",
        "application-list",
        "ssl-ssh-profile",
        "voip-profile",
        "waf-profile",
        "virtual-patch-profile",
        "file-filter-profile",
        "icap-profile",
    }
)
_PROFILE_SECTIONS = {
    "firewall ssl-ssh-profile",
    "firewall profile-protocol-options",
    "firewall webfilter profile",
    "firewall ips sensor",
    "firewall antivirus profile",
    "firewall dnsfilter profile",
    "firewall application list",
    "firewall file-filter profile",
    "firewall virtual-patch profile",
    "firewall waf profile",
    "firewall icap profile",
}
_PROFILE_KEY_TO_TYPE = {
    "webfilter-profile": "webfilter profile",
    "ips-sensor": "ips sensor",
    "av-profile": "antivirus profile",
    "dnsfilter-profile": "dnsfilter profile",
    "application-list": "application list",
    "ssl-ssh-profile": "ssl-ssh-profile",
    "voip-profile": "voip profile",
    "waf-profile": "waf profile",
    "virtual-patch-profile": "virtual-patch profile",
    "file-filter-profile": "file-filter profile",
    "icap-profile": "icap profile",
}


@dataclass(frozen=True)
class FirewallProjection:
    policies: tuple[Policy, ...] = ()
    service_objects: tuple[ServiceObject, ...] = ()
    service_groups: tuple[ServiceObject, ...] = ()
    vips: tuple[Vip, ...] = ()
    vip_groups: tuple[VipGroup, ...] = ()
    virtual_servers: tuple[VirtualServer, ...] = ()
    profile_groups: tuple[ProfileGroup, ...] = ()
    security_profiles: tuple[SecurityProfile, ...] = ()
    log_setting: LogSetting | None = None


def _certain_directives(
    entry: StructuralEntry,
    allowed: frozenset[str],
    *,
    require_entry_certainty: bool = False,
) -> dict[str, StructuralDirective]:
    """Project only one certain write per key, preserving per-key certainty.

    An ambiguous entry can still carry a separately certain risky value.  The
    value is retained for controls that implement FAIL dominance, while the
    projection's proof state remains UNKNOWN for completeness checks.
    """
    result: dict[str, StructuralDirective] = {}
    invalidated = set(entry.invalidated_keys)
    if require_entry_certainty and entry.certainty is not EvidenceCertainty.CERTAIN:
        return result
    for directive in entry.directives:
        if directive.name not in allowed or directive.name in invalidated:
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
    return result


def _section_directives(
    section: StructuralSection,
    allowed: frozenset[str],
) -> dict[str, StructuralDirective]:
    """Keep certain values while section certainty gates completeness proof."""
    result: dict[str, StructuralDirective] = {}
    invalidated = set(section.invalidated_keys)
    for directive in section.directives:
        if directive.name not in allowed or directive.name in invalidated:
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
    return result


def _tokens(directives: dict[str, StructuralDirective], key: str) -> tuple[str, ...]:
    directive = directives.get(key)
    return directive.tokens if directive is not None else ()


def _single(directives: dict[str, StructuralDirective], key: str) -> str | None:
    values = _tokens(directives, key)
    return values[0] if len(values) == 1 else None


def _references(
    tokens: tuple[str, ...], relation: str, object_type: str = "object"
) -> tuple[ObjectReference, ...]:
    return tuple(
        ObjectReference(object_type=object_type, name=token, relation=relation) for token in tokens
    )


def _profile_refs(directives: dict[str, StructuralDirective]) -> tuple[ObjectReference, ...]:
    return tuple(
        reference
        for key, object_type in _PROFILE_KEY_TO_TYPE.items()
        if key in directives
        for reference in _references(_tokens(directives, key), "direct-profile", object_type)
    )


def _parse_port_ranges(tokens: tuple[str, ...]) -> tuple[PortRange, ...] | None:
    def parse_component(value: str) -> tuple[int, int] | None:
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", value)
        if match is None:
            return None
        start = int(match.group(1))
        end = int(match.group(2) or match.group(1))
        return (start, end) if 0 <= start <= end <= 65535 else None

    ranges: list[PortRange] = []
    for token in tokens:
        for value in re.split(r"[\s,]+", token.strip()):
            if not value:
                continue
            components = value.split(":")
            if len(components) > 2:
                return None
            destination = parse_component(components[0])
            source = parse_component(components[1]) if len(components) == 2 else None
            if destination is None or (len(components) == 2 and source is None):
                return None
            ranges.append(PortRange(start=destination[0], end=destination[1]))
    return tuple(ranges)


def _realservers(entry: StructuralEntry) -> tuple[RealServer, ...]:
    result: list[RealServer] = []
    for child in entry.children:
        if child.name.casefold() != "realservers":
            continue
        for server_entry in child.entries:
            directives = _certain_directives(
                server_entry, frozenset({"ip", "port"}), require_entry_certainty=True
            )
            ip = _single(directives, "ip")
            port_value = _single(directives, "port")
            port: int | None = None
            if port_value is not None and port_value.isdecimal():
                candidate = int(port_value)
                if 1 <= candidate <= 65535:
                    port = candidate
            result.append(
                RealServer(
                    name=server_entry.name,
                    ip=ip,
                    port=port,
                    parsed_keys=frozenset(directives),
                    proof_state=(
                        ProofState.PROVEN
                        if server_entry.certainty is EvidenceCertainty.CERTAIN
                        and child.certainty is EvidenceCertainty.CERTAIN
                        and ip is not None
                        and port is not None
                        else ProofState.UNKNOWN
                    ),
                )
            )
    return tuple(result)


def _project_policy(entry: StructuralEntry) -> Policy:
    directives = _certain_directives(entry, _POLICY_KEYS)
    srcintf = _tokens(directives, "srcintf")
    dstintf = _tokens(directives, "dstintf")
    srcaddr = _tokens(directives, "srcaddr")
    dstaddr = _tokens(directives, "dstaddr")
    services = _tokens(directives, "service")
    refs = _references(srcaddr, "source-address") + _references(dstaddr, "destination-address")
    refs += _references(services, "policy-service", "service")
    profile_group = _single(directives, "profile-group")
    profile_reference_cardinality_valid = all(
        len(_tokens(directives, key)) == 1
        for key in (*_PROFILE_GROUP_KEYS, "profile-group")
        if key in directives
    )
    internet_service = _single(directives, "internet-service")
    action = _single(directives, "action")
    direct_profiles = _profile_refs(directives)
    return Policy(
        policy_id=entry.name,
        name=_single(directives, "name"),
        source_interfaces=_references(srcintf, "source-interface", "interface"),
        destination_interfaces=_references(dstintf, "destination-interface", "interface"),
        object_references=refs,
        action=action.casefold() if action is not None else None,
        status=(value.casefold() if (value := _single(directives, "status")) else None),
        schedule=(value.casefold() if (value := _single(directives, "schedule")) else None),
        services=_references(services, "policy-service", "service"),
        logtraffic=(value.casefold() if (value := _single(directives, "logtraffic")) else None),
        utm_status=(value.casefold() if (value := _single(directives, "utm-status")) else None),
        profile_group=(
            _references((profile_group,), "profile-group", "profile-group")[0]
            if profile_group is not None
            else None
        ),
        direct_profile_references=direct_profiles,
        internet_service=(
            internet_service.casefold() == "enable"
            if internet_service is not None and internet_service.casefold() in {"enable", "disable"}
            else None
        ),
        internet_service_names=_references(
            _tokens(directives, "internet-service-name"),
            "internet-service-name",
            "internet-service",
        ),
        parsed_keys=frozenset(directives)
        if entry.certainty is EvidenceCertainty.CERTAIN
        else frozenset(),
        defaulted_keys=frozenset(
            name for name, directive in directives.items() if directive.defaulted
        )
        if entry.certainty is EvidenceCertainty.CERTAIN
        else frozenset(),
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN
            and profile_reference_cardinality_valid
            and all(
                key in directives for key in ("srcintf", "dstintf", "srcaddr", "dstaddr", "action")
            )
            else ProofState.UNKNOWN
        ),
    )


def _project_service(entry: StructuralEntry, service_type: str) -> ServiceObject:
    directives = _certain_directives(entry, _SERVICE_KEYS)
    tcp = (
        _parse_port_ranges(_tokens(directives, "tcp-portrange"))
        if "tcp-portrange" in directives
        else ()
    )
    udp = (
        _parse_port_ranges(_tokens(directives, "udp-portrange"))
        if "udp-portrange" in directives
        else ()
    )
    port_ranges_valid = (
        tcp is not None
        and udp is not None
        and ("tcp-portrange" not in directives or bool(tcp))
        and ("udp-portrange" not in directives or bool(udp))
    )
    members = _references(_tokens(directives, "member"), "service-member", "service")
    protocol = _single(directives, "protocol")
    normalized_protocol = protocol.casefold() if protocol is not None else None
    protocol_cardinality_valid = (
        "protocol" not in directives or len(_tokens(directives, "protocol")) == 1
    )
    protocol_number_token = _single(directives, "protocol-number")
    protocol_number_cardinality_valid = (
        "protocol-number" not in directives
        or len(_tokens(directives, "protocol-number")) == 1
    )
    protocol_number = None
    protocol_number_valid = protocol_number_token is None
    if protocol_number_token is not None:
        try:
            protocol_number = int(protocol_number_token)
            protocol_number_valid = 0 <= protocol_number <= 255
        except ValueError:
            protocol_number_valid = False

    protocol_valid = protocol_number_token is None
    protocol_shape_valid = True
    has_explicit_port_ranges = bool(tcp or udp)
    if normalized_protocol == "all":
        protocol_shape_valid = not has_explicit_port_ranges
        tcp = (PortRange(start=0, end=65535),)
        udp = (PortRange(start=0, end=65535),)
    elif normalized_protocol in {"icmp", "icmp6"}:
        protocol_shape_valid = not has_explicit_port_ranges
    elif normalized_protocol == "ip":
        protocol_valid = protocol_number_valid and protocol_number is not None
        protocol_shape_valid = not has_explicit_port_ranges
        if protocol_number == 6:
            tcp = (PortRange(start=0, end=65535),)
        elif protocol_number == 17:
            udp = (PortRange(start=0, end=65535),)
    elif normalized_protocol == "tcp/udp/sctp" or normalized_protocol is None:
        pass
    else:
        protocol_valid = False

    valid = (
        port_ranges_valid
        and protocol_valid
        and protocol_shape_valid
        and protocol_cardinality_valid
        and protocol_number_cardinality_valid
    )
    has_definition = bool(tcp or udp or members) or normalized_protocol in {
        "all",
        "icmp",
        "icmp6",
        "ip",
    }
    return ServiceObject(
        name=entry.name,
        tcp_port_ranges=tcp or (),
        udp_port_ranges=udp or (),
        members=members,
        service_type=service_type,
        protocol=normalized_protocol,
        protocol_number=protocol_number if protocol_number_valid else None,
        parsed_keys=frozenset(directives)
        if entry.certainty is EvidenceCertainty.CERTAIN
        else frozenset(),
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN and valid and has_definition
            else ProofState.UNKNOWN
        ),
    )


def _project_vip(entry: StructuralEntry) -> Vip | VirtualServer:
    directives = _certain_directives(entry, _VIP_KEYS)
    extintf = _tokens(directives, "extintf")
    vip_type = _single(directives, "type")
    if vip_type is not None and vip_type.casefold() == "server-load-balance":
        servers = _realservers(entry)
        return VirtualServer(
            name=entry.name,
            extintf=extintf,
            realservers=servers,
            vip_type=vip_type,
            parsed_keys=frozenset(directives)
            if entry.certainty is EvidenceCertainty.CERTAIN
            else frozenset(),
            proof_state=(
                ProofState.PROVEN
                if entry.certainty is EvidenceCertainty.CERTAIN
                and "extintf" in directives
                and bool(servers)
                and all(server.proof_state is ProofState.PROVEN for server in servers)
                else ProofState.UNKNOWN
            ),
        )
    return Vip(
        name=entry.name,
        extintf=extintf,
        extip=_single(directives, "extip"),
        mappedip=_tokens(directives, "mappedip"),
        vip_type=vip_type,
        parsed_keys=frozenset(directives)
        if entry.certainty is EvidenceCertainty.CERTAIN
        else frozenset(),
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN
            and all(key in directives for key in ("extintf", "extip", "mappedip"))
            else ProofState.UNKNOWN
        ),
    )


def _project_profile_group(entry: StructuralEntry) -> ProfileGroup:
    directives = _certain_directives(entry, _PROFILE_GROUP_KEYS)
    profile_reference_cardinality_valid = all(
        len(_tokens(directives, key)) == 1 for key in directives
    )
    return ProfileGroup(
        name=entry.name,
        profile_references=_profile_refs(directives),
        parsed_keys=frozenset(directives)
        if entry.certainty is EvidenceCertainty.CERTAIN
        else frozenset(),
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN
            and profile_reference_cardinality_valid
            and bool(directives)
            else ProofState.UNKNOWN
        ),
    )


def _project_vip_group(entry: StructuralEntry) -> VipGroup:
    directives = _certain_directives(entry, frozenset({"member"}))
    members = _references(_tokens(directives, "member"), "vip-member", "vip")
    return VipGroup(
        name=entry.name,
        members=members,
        parsed_keys=(
            frozenset(directives)
            if entry.certainty is EvidenceCertainty.CERTAIN
            else frozenset()
        ),
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN and bool(members)
            else ProofState.UNKNOWN
        ),
    )


def _project_profile(section: StructuralSection, entry: StructuralEntry) -> SecurityProfile:
    directives = _certain_directives(
        entry,
        frozenset({"profile-type", "feature-set", "status"}),
        require_entry_certainty=True,
    )
    namespace_type = section.name.removeprefix("firewall ")
    declared_type = _single(directives, "profile-type")
    settings = _references(
        _tokens(directives, "feature-set"),
        "profile-setting",
        declared_type or namespace_type,
    )
    return SecurityProfile(
        name=entry.name,
        profile_type=namespace_type,
        settings=settings,
        parsed_keys=frozenset(directives),
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN and bool(directives)
            else ProofState.UNKNOWN
        ),
    )


def project_firewall(document: StructuralDocument) -> FirewallProjection:
    policies: list[Policy] = []
    service_objects: list[ServiceObject] = []
    service_groups: list[ServiceObject] = []
    vips: list[Vip] = []
    vip_groups: list[VipGroup] = []
    virtual_servers: list[VirtualServer] = []
    profile_groups: list[ProfileGroup] = []
    security_profiles: list[SecurityProfile] = []
    log_setting: LogSetting | None = None

    for section in document.sections:
        if section.name == "firewall policy":
            policies.extend(_project_policy(entry) for entry in section.entries)
        elif section.name in {"firewall service custom", "firewall service group"}:
            service_type = "group" if section.name.endswith("group") else "custom"
            target = service_groups if service_type == "group" else service_objects
            target.extend(_project_service(entry, service_type) for entry in section.entries)
        elif section.name == "firewall vip":
            for entry in section.entries:
                projection = _project_vip(entry)
                if isinstance(projection, VirtualServer):
                    virtual_servers.append(projection)
                else:
                    vips.append(projection)
        elif section.name == "firewall profile-group":
            profile_groups.extend(_project_profile_group(entry) for entry in section.entries)
        elif section.name == "firewall vipgrp":
            vip_groups.extend(_project_vip_group(entry) for entry in section.entries)
        elif section.name in _PROFILE_SECTIONS:
            security_profiles.extend(_project_profile(section, entry) for entry in section.entries)
        elif section.name == "log setting":
            directives = _section_directives(section, frozenset({"fwpolicy-implicit-log"}))
            value = _single(directives, "fwpolicy-implicit-log")
            log_setting = LogSetting(
                implicit_deny_log=value.casefold() if value is not None else None,
                parsed_keys=frozenset(directives),
                proof_state=(
                    ProofState.PROVEN
                    if value is not None and section.certainty is EvidenceCertainty.CERTAIN
                    else ProofState.UNKNOWN
                ),
            )

    return FirewallProjection(
        policies=tuple(policies),
        service_objects=tuple(service_objects),
        service_groups=tuple(service_groups),
        vips=tuple(vips),
        vip_groups=tuple(vip_groups),
        virtual_servers=tuple(virtual_servers),
        profile_groups=tuple(profile_groups),
        security_profiles=tuple(security_profiles),
        log_setting=log_setting,
    )


def apply_firewall_projection(
    configuration: FortiGateConfiguration,
    projection: FirewallProjection,
) -> FortiGateConfiguration:
    """Attach typed firewall projections without exposing raw configuration text."""
    return configuration.model_copy(
        update={
            "policies": projection.policies or configuration.policies,
            "service_objects": projection.service_objects,
            "service_groups": projection.service_groups,
            "vips": projection.vips,
            "vip_groups": projection.vip_groups,
            "virtual_servers": projection.virtual_servers,
            "profile_groups": projection.profile_groups,
            "security_profiles": projection.security_profiles or configuration.security_profiles,
            "log_setting": projection.log_setting,
            "implicit_deny_log": (
                projection.log_setting.implicit_deny_log if projection.log_setting else None
            ),
            "object_references": tuple(
                reference
                for policy in (projection.policies or configuration.policies)
                for reference in policy.object_references
            ),
        }
    )
