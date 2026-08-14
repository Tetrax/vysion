import re
import unicodedata
from dataclasses import dataclass, field

from vysion.audit.firewall_projection import apply_firewall_projection, project_firewall
from vysion.audit.models import (
    Administrator,
    DeviceIdentity,
    EvidenceCertainty,
    FortiGateConfiguration,
    Interface,
    LocalUser,
    ObjectReference,
    Policy,
    ProofState,
    SecondaryIP,
    SecurityProfile,
    StructuralDirective,
    StructuralDocument,
    StructuralEntry,
    StructuralSection,
    Zone,
)
from vysion.audit.utm_projection import apply_utm_projection, project_utm
from vysion.audit.vpn_projection import apply_vpn_projection, project_vpn

_AUDITED_ENTRY_SECTIONS = {"system interface", "system admin"}
_AUDITED_SECTIONS = _AUDITED_ENTRY_SECTIONS | {"system global"}
_ENTRY_ONLY_NAMESPACES = {"system admin", "user local", "user ldap"}
_ALLOWED_CONTROLS = {"\n", "\r", "\t"}
_RELEVANT_KEYS = {
    "system global": {"hostname"},
    "system interface": {"ip", "allowaccess", "role"},
    "system admin": {"peer-auth", "two-factor"},
}
_TOLERATED_NON_PROBATIVE_KEYS = {
    "system global": {"admin-sport", "admintimeout", "timezone"},
    "system interface": {"alias", "description", "type", "vdom"},
    "system admin": {"accprofile", "email-to", "vdom"},
}
_TOLERATED_CHILD_SECTIONS = {
    "system global": frozenset(),
    "system interface": frozenset({"secondaryip"}),
    "system admin": frozenset({"dashboard"}),
}
_MUTATION_DIRECTIVES = {"append", "select", "unselect", "unset"}
_RESERVED_DIRECTIVES = _MUTATION_DIRECTIVES | {"config", "edit", "end", "next", "set"}
_PROJECTED_SECTIONS = {
    "system zone",
    "firewall policy",
    "firewall service custom",
    "firewall service group",
    "firewall vip",
    "firewall vipgrp",
    "firewall profile-group",
    "firewall webfilter profile",
    "firewall ips sensor",
    "firewall antivirus profile",
    "firewall dnsfilter profile",
    "firewall application list",
    "firewall file-filter profile",
    "firewall virtual-patch profile",
    "firewall waf profile",
    "firewall icap profile",
    "log setting",
    "user local",
    "user ldap",
    "firewall ssl-ssh-profile",
    "firewall profile-protocol-options",
    "vpn ssl settings",
    "vpn ipsec phase1-interface",
    "vpn ipsec phase2-interface",
    "webfilter profile",
    "antivirus profile",
    "ips sensor",
    "application list",
    "dnsfilter profile",
    "system autoupdate schedule",
    "system external-resource",
    "firewall internet-service-group",
}
_PROJECTED_KEYS = {
    "system zone": {"interface"},
    "firewall policy": {
        "name", "srcintf", "dstintf", "srcaddr", "dstaddr", "action", "status",
        "schedule", "service", "logtraffic", "utm-status", "profile-group",
        "webfilter-profile", "ips-sensor", "av-profile", "dnsfilter-profile",
        "application-list", "ssl-ssh-profile", "voip-profile", "waf-profile",
        "virtual-patch-profile", "file-filter-profile", "icap-profile",
        "internet-service", "internet-service-name",
        "internet-service-src-name", "internet-service-group",
        "internet-service-src-group",
    },
    "firewall service custom": {"tcp-portrange", "udp-portrange", "member"},
    "firewall service group": {"member"},
    "firewall vip": {"extintf", "extip", "mappedip", "type"},
    "firewall vipgrp": {"member"},
    "firewall profile-group": {
        "webfilter-profile", "ips-sensor", "av-profile", "dnsfilter-profile",
        "application-list", "ssl-ssh-profile", "voip-profile", "waf-profile",
        "virtual-patch-profile", "file-filter-profile", "icap-profile",
    },
    "firewall webfilter profile": {"feature-set"},
    "firewall ips sensor": {"status"},
    "firewall antivirus profile": {"feature-set"},
    "firewall dnsfilter profile": {"feature-set"},
    "firewall application list": {"feature-set"},
    "firewall file-filter profile": {"feature-set"},
    "firewall virtual-patch profile": {"feature-set"},
    "firewall waf profile": {"feature-set"},
    "firewall icap profile": {"feature-set"},
    "log setting": {"fwpolicy-implicit-log"},
    "user local": {"type", "two-factor"},
    "user ldap": {"secure", "ca-cert"},
    "firewall ssl-ssh-profile": {"profile-type"},
    "firewall profile-protocol-options": {"profile-type"},
    "vpn ssl settings": {"status", "source-interface"},
    "vpn ipsec phase1-interface": {"status", "interface", "ike-version", "proposal", "dhgrp"},
    "vpn ipsec phase2-interface": {
        "status", "phase1name", "pfs", "proposal", "dhgrp"
    },
    "system autoupdate schedule": {"status", "frequency"},
    "system external-resource": {"status"},
    "firewall internet-service-group": {"member"},
}
_PROJECTED_TOLERATED_NON_PROBATIVE_KEYS = {
    "firewall policy": frozenset({"comment"}),
}
_PROJECTED_CHILD_KEYS = {
    "secondaryip": {"ip", "allowaccess"},
    "dashboard": {"name"},
    "realservers": {"ip", "port"},
    "web": {"blocklist"},
    "ftgd-wf": {"options"},
    "ftgd-dns": {"options"},
    "filters": {"category", "action"},
    "entries": {"category", "action"},
}
_PROJECTED_CHILDREN = {
    "system interface": frozenset({"secondaryip"}),
    "system admin": frozenset({"dashboard"}),
    "firewall vip": frozenset({"realservers"}),
    "webfilter profile": frozenset({"web", "ftgd-wf"}),
    "dnsfilter profile": frozenset({"ftgd-dns"}),
    "application list": frozenset({"entries"}),
    "ftgd-wf": frozenset({"filters"}),
    "ftgd-dns": frozenset({"filters"}),
    "secondaryip": frozenset(),
    "dashboard": frozenset(),
    "realservers": frozenset(),
    "web": frozenset(),
    "filters": frozenset(),
    "entries": frozenset(),
}
_SECTION_SEPARATORS = re.compile(r"[\s._/-]+")
_SUPPORTED_ALLOWACCESS = {
    "fabric",
    "fgfm",
    "ftm",
    "http",
    "https",
    "ping",
    "probe-response",
    "radius-acct",
    "snmp",
    "speed-test",
    "ssh",
    "telnet",
}
_SUPPORTED_PEER_AUTH = {"enable", "disable"}
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z"
)
_CONFIG_VERSION = re.compile(
    r"#config-version=FGT?(?P<model>[A-Z0-9]+)-"
    r"(?P<version>[0-9]+(?:\.[0-9]+){1,3})"
    r"(?:-FW-build[0-9]+-[0-9]+)?(?::.*)?\Z"
)


def _reject_dangerous_characters(raw: str) -> None:
    for character in raw:
        if character in _ALLOWED_CONTROLS:
            continue
        if character in {"\u2028", "\u2029"}:
            raise ValueError("invalid line separator in configuration")
        category = unicodedata.category(character)
        if ord(character) == 0x7F or category in {"Cc", "Cf"}:
            raise ValueError("invalid control character in configuration")


def _payload(line: str, keyword: str, error: str) -> str:
    if not line.startswith(keyword) or len(line) == len(keyword):
        raise ValueError(error)
    payload = line[len(keyword) :]
    if not payload[0].isspace():
        raise ValueError(error)
    payload = payload.strip()
    if not payload:
        raise ValueError(error)
    return payload


def _tokens(payload: str, error: str) -> list[str]:
    if "'" in payload or "\\" in payload:
        raise ValueError(error)
    tokens: list[str] = []
    position = 0
    while position < len(payload):
        while position < len(payload) and payload[position].isspace():
            position += 1
        if position == len(payload):
            break
        if payload[position] == '"':
            position += 1
            start = position
            while position < len(payload) and payload[position] != '"':
                position += 1
            if position == len(payload):
                raise ValueError(error)
            tokens.append(payload[start:position])
            position += 1
            if position < len(payload) and not payload[position].isspace():
                raise ValueError(error)
        else:
            start = position
            while position < len(payload) and not payload[position].isspace():
                if payload[position] == '"':
                    raise ValueError(error)
                position += 1
            tokens.append(payload[start:position])
    if not tokens:
        raise ValueError(error)
    return tokens


def _key_and_value(payload: str, error: str) -> tuple[str, str | None]:
    if payload.startswith('"'):
        closing_quote = payload.find('"', 1)
        if closing_quote == -1:
            raise ValueError(error)
        key = payload[1:closing_quote]
        remainder = payload[closing_quote + 1 :]
        if remainder and not remainder[0].isspace():
            raise ValueError(error)
        value = remainder.strip() or None
    else:
        parts = payload.split(maxsplit=1)
        key = parts[0]
        value = parts[1] if len(parts) == 2 else None
    if not key or "'" in key or "\\" in key or '"' in key:
        raise ValueError(error)
    return key.lower(), value


def _best_effort_tokens(payload: str | None) -> tuple[str, ...]:
    if not payload:
        return ()
    try:
        return tuple(_tokens(payload, "ambiguous directive"))
    except ValueError:
        # Unknown sections are traversed but never used as audit evidence. Keep
        # only one opaque token rather than retaining a line or raw config.
        return (payload,)


@dataclass
class _Frame:
    section: str
    audited_section: str | None
    line: int
    entry_name: str | None = None
    entry_line: int | None = None
    values: dict[str, str] = field(default_factory=dict)
    uncertain_keys: set[str] = field(default_factory=set)
    directives: list[StructuralDirective] = field(default_factory=list)
    entries: list[StructuralEntry] = field(default_factory=list)
    children: list["_Frame"] = field(default_factory=list)
    entry_children: list["_Frame"] = field(default_factory=list)
    entry_directives: list[StructuralDirective] = field(default_factory=list)
    entry_structural_keys: set[str] = field(default_factory=set)
    entry_certainty: EvidenceCertainty = EvidenceCertainty.CERTAIN
    certainty: EvidenceCertainty = EvidenceCertainty.CERTAIN

    def record(self, directive: StructuralDirective) -> None:
        if self.entry_name is None:
            self.directives.append(directive)
        else:
            self.entry_directives.append(directive)
            self.entry_structural_keys.add(directive.name)

    def invalidate(self, key: str) -> None:
        self.values.pop(key, None)
        self.uncertain_keys.add(key)
        if self.entry_name is None:
            self.certainty = EvidenceCertainty.AMBIGUOUS
        else:
            self.entry_certainty = EvidenceCertainty.AMBIGUOUS

    def mark_ambiguous(self) -> None:
        if self.entry_name is None:
            self.certainty = EvidenceCertainty.AMBIGUOUS
        else:
            self.entry_certainty = EvidenceCertainty.AMBIGUOUS

    def flush_entry(self) -> None:
        if self.entry_name is None:
            return
        entry_certainty = self.entry_certainty
        if self.certainty is not EvidenceCertainty.CERTAIN:
            entry_certainty = EvidenceCertainty.AMBIGUOUS
        if self.audited_section == "user ldap" and self.entry_children:
            entry_certainty = EvidenceCertainty.AMBIGUOUS
        child_sections = [_structural_section(child) for child in self.entry_children]
        child_counts: dict[str, int] = {}
        for child in child_sections:
            child_counts[child.name.casefold()] = child_counts.get(child.name.casefold(), 0) + 1
        normalized_children: list[StructuralSection] = []
        for child in child_sections:
            if child_counts[child.name.casefold()] > 1:
                entry_certainty = EvidenceCertainty.AMBIGUOUS
                normalized_children.append(
                    child.model_copy(
                        update={
                            "parsed_keys": frozenset(),
                            "invalidated_keys": frozenset(
                                set(child.invalidated_keys) | set(child.parsed_keys)
                            ),
                            "certainty": EvidenceCertainty.AMBIGUOUS,
                        }
                    )
                )
            else:
                normalized_children.append(child)
        if any(child.certainty is not EvidenceCertainty.CERTAIN for child in normalized_children):
            entry_certainty = EvidenceCertainty.AMBIGUOUS
        # ``user ldap`` is a flat projected namespace.  A nested block must
        # never be allowed to look like additional connector evidence, even
        # when its own syntax is otherwise well-formed.
        entry_invalidated_keys = set(self.uncertain_keys)
        if self.section == "user ldap" and normalized_children:
            entry_certainty = EvidenceCertainty.AMBIGUOUS
            entry_invalidated_keys.update(self.entry_structural_keys)
        entry = StructuralEntry(
            name=self.entry_name,
            line=self.entry_line or self.line,
            directives=tuple(self.entry_directives),
            children=tuple(normalized_children),
            parsed_keys=frozenset(self.entry_structural_keys - entry_invalidated_keys),
            invalidated_keys=frozenset(entry_invalidated_keys),
            certainty=entry_certainty,
        )
        self.entries.append(entry)
        self.entry_name = None
        self.entry_line = None
        self.values = {}
        self.uncertain_keys = set()
        self.entry_children = []
        self.entry_directives = []
        self.entry_structural_keys = set()
        self.entry_certainty = EvidenceCertainty.CERTAIN


def _structural_section(frame: _Frame) -> StructuralSection:
    parsed_keys = {
        directive.name
        for directive in frame.directives
        if directive.certainty is EvidenceCertainty.CERTAIN and not directive.mutation
    }
    child_sections = tuple(_structural_section(child) for child in frame.children)
    child_counts: dict[str, int] = {}
    for child in child_sections:
        key = child.name.casefold()
        child_counts[key] = child_counts.get(key, 0) + 1
    children: list[StructuralSection] = []
    certainty = frame.certainty
    if frame.section in _ENTRY_ONLY_NAMESPACES and (frame.directives or frame.children):
        certainty = EvidenceCertainty.AMBIGUOUS
    if any(child.certainty is not EvidenceCertainty.CERTAIN for child in child_sections):
        certainty = EvidenceCertainty.AMBIGUOUS
    for child in child_sections:
        if child_counts[child.name.casefold()] > 1:
            certainty = EvidenceCertainty.AMBIGUOUS
            children.append(
                child.model_copy(
                    update={
                        "parsed_keys": frozenset(),
                        "invalidated_keys": frozenset(
                            set(child.invalidated_keys) | set(child.parsed_keys)
                        ),
                        "certainty": EvidenceCertainty.AMBIGUOUS,
                    }
                )
            )
        else:
            children.append(child)
    entry_counts: dict[str, int] = {}
    for entry in frame.entries:
        key = entry.name.casefold()
        entry_counts[key] = entry_counts.get(key, 0) + 1
    entries: list[StructuralEntry] = []
    for entry in frame.entries:
        if entry_counts[entry.name.casefold()] > 1:
            certainty = EvidenceCertainty.AMBIGUOUS
            entries.append(
                entry.model_copy(
                    update={
                        "parsed_keys": frozenset(),
                        "invalidated_keys": frozenset(
                            set(entry.invalidated_keys) | set(entry.parsed_keys)
                        ),
                        "certainty": EvidenceCertainty.AMBIGUOUS,
                    }
                )
            )
        else:
            entries.append(entry)
    if any(entry.certainty is not EvidenceCertainty.CERTAIN for entry in entries):
        certainty = EvidenceCertainty.AMBIGUOUS
    return StructuralSection(
        name=frame.section,
        line=frame.line,
        directives=tuple(frame.directives),
        entries=tuple(entries),
        children=tuple(children),
        parsed_keys=frozenset(parsed_keys),
        invalidated_keys=frozenset(frame.uncertain_keys),
        certainty=certainty,
    )


def _directive_map(entry: StructuralEntry) -> dict[str, StructuralDirective]:
    """Return certain, non-mutated directives not invalidated by the entry."""
    result: dict[str, StructuralDirective] = {}
    invalidated: set[str] = set(entry.invalidated_keys)
    for directive in entry.directives:
        if directive.name in invalidated:
            continue
        if directive.certainty is not EvidenceCertainty.CERTAIN or directive.mutation:
            invalidated.add(directive.name)
            result.pop(directive.name, None)
            continue
        if directive.name in result:
            invalidated.add(directive.name)
            result.pop(directive.name, None)
            continue
        result[directive.name] = directive
    return result


def _observed_tokens(entry: StructuralEntry, name: str) -> tuple[str, ...]:
    """Keep one explicit value as observation, never as compliance proof."""
    if any(
        directive.name == name and directive.mutation
        for directive in entry.directives
    ):
        return ()
    directives = tuple(
        directive
        for directive in entry.directives
        if directive.name == name and not directive.mutation
    )
    if len(directives) != 1:
        return ()
    return tuple(token.casefold() for token in directives[0].tokens)


def _section_directive_map(section: StructuralSection) -> dict[str, StructuralDirective]:
    """Return certain top-level directives not invalidated by the section."""
    result: dict[str, StructuralDirective] = {}
    invalidated: set[str] = set(section.invalidated_keys)
    for directive in section.directives:
        if directive.name in invalidated:
            continue
        if directive.certainty is not EvidenceCertainty.CERTAIN or directive.mutation:
            invalidated.add(directive.name)
            result.pop(directive.name, None)
            continue
        if directive.name in result:
            invalidated.add(directive.name)
            result.pop(directive.name, None)
            continue
        result[directive.name] = directive
    return result


def _secondary_ip_projection(
    interface_name: str,
    children: tuple[StructuralSection, ...],
) -> tuple[SecondaryIP, ...]:
    """Project ``config secondaryip`` without borrowing parent directives."""

    secondary_ips: list[SecondaryIP] = []
    for child in children:
        if child.name.casefold() != "secondaryip":
            continue
        for entry in child.entries:
            directives = _directive_map(entry)
            ip = directives.get("ip")
            allowaccess = directives.get("allowaccess")
            allowaccess_values = (
                frozenset(token.casefold() for token in allowaccess.tokens)
                if allowaccess is not None
                else frozenset(_observed_tokens(entry, "allowaccess"))
            )
            allowaccess_is_supported = allowaccess_values <= _SUPPORTED_ALLOWACCESS
            secondary_ips.append(
                SecondaryIP(
                    name=f"{interface_name}.secondaryip[{entry.name}]",
                    address=" ".join(ip.tokens) if ip is not None else None,
                    allowaccess=allowaccess_values,
                    parsed_keys=frozenset(directives),
                    proof_state=(
                        ProofState.PROVEN
                        if allowaccess is not None
                        and allowaccess_is_supported
                        and ip is not None
                        and child.certainty is EvidenceCertainty.CERTAIN
                        and entry.certainty is EvidenceCertainty.CERTAIN
                        else ProofState.UNKNOWN
                    ),
                )
            )
    return tuple(secondary_ips)


def _projection_directives(
    entry: StructuralEntry,
    section_name: str,
) -> dict[str, StructuralDirective]:
    return {
        name: directive
        for name, directive in _directive_map(entry).items()
        if name in _PROJECTED_KEYS[section_name]
    }


def _references(
    tokens: tuple[str, ...],
    relation: str,
    object_type: str = "object",
) -> tuple[ObjectReference, ...]:
    return tuple(
        ObjectReference(object_type=object_type, name=token, relation=relation)
        for token in tokens
    )


def _project_generic_sections(
    document: StructuralDocument,
) -> tuple[
    tuple[Zone, ...],
    tuple[Policy, ...],
    tuple[LocalUser, ...],
    tuple[SecurityProfile, ...],
]:
    zones: list[Zone] = []
    policies: list[Policy] = []
    local_users: list[LocalUser] = []
    security_profiles: list[SecurityProfile] = []

    for section in document.sections:
        if section.certainty is EvidenceCertainty.INVALID:
            continue
        if section.name == "system zone":
            for entry in section.entries:
                directives = _projection_directives(entry, section.name)
                interface = directives.get("interface")
                zones.append(
                    Zone(
                        name=entry.name,
                        interfaces=(
                            _references(tuple(interface.tokens), "zone-interface", "interface")
                            if interface is not None
                            else ()
                        ),
                        parsed_keys=frozenset(directives),
                        proof_state=(
                            ProofState.PROVEN if interface is not None else ProofState.UNKNOWN
                        ),
                    )
                )
        elif section.name == "firewall policy":
            for entry in section.entries:
                directives = _projection_directives(entry, section.name)
                srcintf = directives.get("srcintf")
                dstintf = directives.get("dstintf")
                srcaddr = directives.get("srcaddr")
                dstaddr = directives.get("dstaddr")
                name = directives.get("name")
                action = directives.get("action")
                policies.append(
                    Policy(
                        policy_id=entry.name,
                        name=(name.tokens[0] if name and name.tokens else None),
                        source_interfaces=(
                            _references(
                                tuple(srcintf.tokens), "source-interface", "interface"
                            )
                            if srcintf is not None
                            else ()
                        ),
                        destination_interfaces=(
                            _references(
                                tuple(dstintf.tokens), "destination-interface", "interface"
                            )
                            if dstintf is not None
                            else ()
                        ),
                        object_references=(
                            _references(
                                tuple(srcaddr.tokens) if srcaddr is not None else (),
                                "source-address",
                            )
                            + _references(
                                tuple(dstaddr.tokens) if dstaddr is not None else (),
                                "destination-address",
                            )
                        ),
                        action=(action.tokens[0] if action and action.tokens else None),
                        parsed_keys=frozenset(directives),
                        proof_state=(
                            ProofState.PROVEN
                            if srcintf is not None
                            and dstintf is not None
                            and srcaddr is not None
                            and dstaddr is not None
                            else ProofState.UNKNOWN
                        ),
                    )
                )
        elif section.name == "user local":
            for entry in section.entries:
                directives = _projection_directives(entry, section.name)
                user_type = directives.get("type")
                two_factor = directives.get("two-factor")
                local_users.append(
                    LocalUser(
                        name=entry.name,
                        type=(user_type.tokens[0] if user_type and user_type.tokens else None),
                        two_factor=(
                            two_factor.tokens[0]
                            if two_factor and two_factor.tokens
                            else None
                        ),
                        parsed_keys=frozenset(directives),
                        proof_state=ProofState.PROVEN if directives else ProofState.UNKNOWN,
                    )
                )
        elif section.name in {"firewall ssl-ssh-profile", "firewall profile-protocol-options"}:
            for entry in section.entries:
                directives = _projection_directives(entry, section.name)
                profile_type = directives.get("profile-type")
                security_profiles.append(
                    SecurityProfile(
                        name=entry.name,
                        profile_type=(
                            profile_type.tokens[0]
                            if profile_type and profile_type.tokens
                            else None
                        ),
                        settings=_references(
                            tuple(profile_type.tokens) if profile_type else (),
                            "profile-type",
                        ),
                        parsed_keys=frozenset(directives),
                        proof_state=(
                            ProofState.PROVEN
                            if profile_type is not None
                            else ProofState.UNKNOWN
                        ),
                    )
                )
    return tuple(zones), tuple(policies), tuple(local_users), tuple(security_profiles)


class FortiGateParser:
    def parse(self, raw: str) -> FortiGateConfiguration:
        raw = raw.removeprefix("\ufeff")
        _reject_dangerous_characters(raw)

        config_headers = tuple(
            match
            for original_line in raw.splitlines()
            if (match := _CONFIG_VERSION.fullmatch(original_line.strip())) is not None
        )
        identity_model: str | None = None
        firmware_version: str | None = None
        identity_keys: set[str] = set()
        if len(config_headers) == 1:
            identity_model = config_headers[0].group("model")
            firmware_version = config_headers[0].group("version")
            identity_keys.update({"model", "firmware-version"})

        hostname: str | None = None
        hostname_proven = False
        interfaces: list[Interface] = []
        administrators: list[Administrator] = []
        parsed_sections: set[str] = set()
        parsed_entry_sections: set[str] = set()
        stack: list[_Frame] = []
        top_level_frames: list[_Frame] = []
        saw_configuration = False

        def flush_entry(frame: _Frame) -> None:
            if frame.entry_name is None:
                return
            values = dict(frame.values)
            frame.flush_entry()
            entry = frame.entries[-1]
            if frame.audited_section == "system interface":
                parsed_entry_sections.add(frame.audited_section)
                interfaces.append(
                    Interface(
                        name=entry.name,
                        address=values.get("ip"),
                        allowaccess=(
                            frozenset(values["allowaccess"].lower().split())
                            if "allowaccess" in values
                            else frozenset(_observed_tokens(entry, "allowaccess"))
                        ),
                        role=values.get("role", "").lower() or None,
                        secondary_ips=_secondary_ip_projection(entry.name, entry.children),
                        parsed_keys=frozenset(values),
                        proof_state=(
                            ProofState.PROVEN
                            if "allowaccess" in values
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            else ProofState.UNKNOWN
                        ),
                    )
                )
            elif frame.audited_section == "system admin":
                parsed_entry_sections.add(frame.audited_section)
                administrators.append(
                    Administrator(
                        name=entry.name,
                        two_factor=(
                            values["two-factor"].lower()
                            if "two-factor" in values
                            else None
                        ),
                        peer_auth=(
                            values["peer-auth"].casefold() == "enable"
                            if "peer-auth" in values
                            else None
                        ),
                        parsed_keys=frozenset(values),
                        proof_state=(
                            ProofState.PROVEN
                            if ("two-factor" in values or "peer-auth" in values)
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            else ProofState.UNKNOWN
                        ),
                    )
                )

        def record_generic_set(frame: _Frame, line: str, line_number: int) -> None:
            try:
                payload = _payload(line, "set", "malformed set directive")
            except ValueError:
                frame.mark_ambiguous()
                frame.invalidate("<malformed>")
                frame.record(
                    StructuralDirective(
                        name="set",
                        line=line_number,
                        certainty=EvidenceCertainty.AMBIGUOUS,
                    )
                )
                return
            try:
                key, value_payload = _key_and_value(payload, "malformed set directive")
                raw_key = payload.split(maxsplit=1)[0]
                if raw_key.startswith('"') and raw_key.endswith('"'):
                    raw_key = raw_key[1:-1]
                if value_payload is None:
                    tokens = ()
                    certainty = EvidenceCertainty.AMBIGUOUS
                else:
                    tokens = tuple(_tokens(value_payload, "malformed set directive"))
                    certainty = (
                        EvidenceCertainty.CERTAIN
                        if tokens
                        else EvidenceCertainty.AMBIGUOUS
                    )
                if frame.section == "user ldap" and raw_key != key:
                    certainty = EvidenceCertainty.AMBIGUOUS
            except ValueError:
                parts = payload.split(maxsplit=1)
                key = parts[0].lower() if parts else "set"
                raw_key = parts[0] if parts else "set"
                tokens = _best_effort_tokens(parts[1] if len(parts) == 2 else None)
                certainty = EvidenceCertainty.AMBIGUOUS
            existing_keys = {
                directive.name
                for directive in frame.entry_directives
                if not directive.mutation
            }
            if key in existing_keys or key in frame.uncertain_keys:
                frame.invalidate(key)
            if certainty is EvidenceCertainty.AMBIGUOUS:
                frame.invalidate(key)
            projected_keys = _PROJECTED_KEYS.get(frame.section) or _PROJECTED_CHILD_KEYS.get(
                frame.section
            )
            tolerated_keys = _PROJECTED_TOLERATED_NON_PROBATIVE_KEYS.get(
                frame.section, frozenset()
            )
            if projected_keys is not None and (
                raw_key != key or key not in projected_keys | tolerated_keys
            ):
                frame.mark_ambiguous()
            frame.record(
                StructuralDirective(
                    name=key,
                    tokens=tokens,
                    line=line_number,
                    certainty=certainty,
                )
            )
            if certainty is EvidenceCertainty.AMBIGUOUS:
                frame.mark_ambiguous()

        for line_number, original_line in enumerate(raw.splitlines(), start=1):
            line = original_line.strip()
            if not line or line.startswith("#"):
                continue

            keyword = line.split(maxsplit=1)[0]
            normalized_keyword = keyword.lower()
            if keyword != normalized_keyword and normalized_keyword in _RESERVED_DIRECTIVES:
                raise ValueError("ambiguous directive")
            if (
                stack
                and stack[-1].audited_section is not None
                and any(
                    normalized_keyword.startswith(reserved) for reserved in _RESERVED_DIRECTIVES
                )
                and normalized_keyword not in _RESERVED_DIRECTIVES
            ):
                raise ValueError("ambiguous directive")
            if keyword == "config":
                config_tokens = _tokens(
                    _payload(line, "config", "malformed config directive"),
                    "malformed config directive",
                )
                raw_section = " ".join(" ".join(config_tokens).split())
                section = raw_section.lower()
                is_top_level = not stack
                if not is_top_level and section in _PROJECTED_SECTIONS:
                    raise ValueError("nested projected section")
                compact_section = _SECTION_SEPARATORS.sub("", section)
                resembles_audited = any(
                    section.startswith(audited)
                    or compact_section.startswith(_SECTION_SEPARATORS.sub("", audited))
                    for audited in _AUDITED_SECTIONS
                )
                if resembles_audited and (not is_top_level or section not in _AUDITED_SECTIONS):
                    raise ValueError("ambiguous or nested audited section")
                if stack and stack[-1].audited_section is not None:
                    parent = stack[-1]
                    parent_section = parent.audited_section
                    assert parent_section is not None
                    allowed_children = _TOLERATED_CHILD_SECTIONS[parent_section]
                    if section not in allowed_children:
                        parent.mark_ambiguous()
                        if parent_section == "system global":
                            hostname_proven = False
                audited_section = section if is_top_level and section in _AUDITED_SECTIONS else None
                if audited_section is not None and audited_section in parsed_sections:
                    raise ValueError("duplicate audited section")
                if section in _PROJECTED_SECTIONS and section in parsed_sections:
                    raise ValueError("duplicate projected section")
                frame = _Frame(section=section, audited_section=audited_section, line=line_number)
                is_projected_shape = (
                    section in _AUDITED_SECTIONS
                    or section in _PROJECTED_SECTIONS
                    or section in _PROJECTED_CHILD_KEYS
                )
                if is_projected_shape and raw_section != section:
                    frame.certainty = EvidenceCertainty.AMBIGUOUS
                if stack:
                    parent_section = stack[-1].section
                    allowed_children = _PROJECTED_CHILDREN.get(parent_section)
                    if (
                        allowed_children is not None and section not in allowed_children
                    ) or (parent_section in _PROJECTED_SECTIONS and allowed_children is None):
                        frame.certainty = EvidenceCertainty.AMBIGUOUS
                if stack:
                    if stack[-1].entry_name is None:
                        stack[-1].children.append(frame)
                    else:
                        stack[-1].entry_children.append(frame)
                else:
                    top_level_frames.append(frame)
                stack.append(frame)
                if is_top_level:
                    parsed_sections.add(section)
                saw_configuration = True
                continue

            if keyword == "edit":
                if stack and stack[-1].audited_section == "system global":
                    raise ValueError("unsupported edit in audited section")
                if not stack or stack[-1].entry_name is not None:
                    raise ValueError(
                        f"unsupported or incomplete FortiGate configuration at line {line_number}"
                    )
                edit_payload = _payload(line, "edit", "malformed edit directive")
                frame = stack[-1]
                entry_certainty = EvidenceCertainty.CERTAIN
                if frame.audited_section is None:
                    try:
                        edit_tokens = _tokens(edit_payload, "malformed edit directive")
                        entry_name = edit_tokens[0] if len(edit_tokens) == 1 else "<opaque>"
                        if len(edit_tokens) != 1:
                            entry_certainty = EvidenceCertainty.AMBIGUOUS
                    except ValueError:
                        # Preserve legacy traversal of non-audited sections while
                        # making the structural entry explicitly non-probative.
                        entry_name = "<opaque>"
                        entry_certainty = EvidenceCertainty.AMBIGUOUS
                else:
                    edit_tokens = _tokens(edit_payload, "malformed edit directive")
                    if len(edit_tokens) != 1:
                        raise ValueError("malformed edit directive")
                    entry_name = edit_tokens[0]
                    if any(
                        entry.name.casefold() == entry_name.casefold()
                        for entry in frame.entries
                    ):
                        raise ValueError("duplicate audited entry")
                frame.entry_name = entry_name
                frame.entry_line = line_number
                frame.entry_certainty = entry_certainty
                frame.values = {}
                frame.uncertain_keys = set()
                frame.entry_children = []
                frame.entry_directives = []
                frame.entry_structural_keys = set()
                continue

            if keyword == "next":
                if line != "next" or not stack or stack[-1].entry_name is None:
                    raise ValueError(
                        f"unsupported or incomplete FortiGate configuration at line {line_number}"
                    )
                flush_entry(stack[-1])
                continue

            if keyword == "end":
                if line != "end" or not stack or stack[-1].entry_name is not None:
                    raise ValueError(
                        f"unsupported or incomplete FortiGate configuration at line {line_number}"
                    )
                stack.pop()
                continue

            if keyword == "set":
                if not stack:
                    raise ValueError(f"set outside configuration block at line {line_number}")
                frame = stack[-1]
                if frame.audited_section is None:
                    record_generic_set(frame, line, line_number)
                    continue
                if frame.audited_section in _AUDITED_ENTRY_SECTIONS and frame.entry_name is None:
                    raise ValueError("directive outside audited entry")

                payload = _payload(line, "set", "malformed set directive")
                key, value_payload = _key_and_value(payload, "malformed set directive")
                raw_key = payload.split(maxsplit=1)[0]
                if raw_key != key:
                    frame.mark_ambiguous()
                if key not in _RELEVANT_KEYS[frame.audited_section]:
                    if key not in _TOLERATED_NON_PROBATIVE_KEYS[frame.audited_section]:
                        frame.mark_ambiguous()
                        if frame.audited_section == "system global":
                            hostname_proven = False
                    frame.record(
                        StructuralDirective(
                            name=key,
                            tokens=_best_effort_tokens(value_payload),
                            line=line_number,
                        )
                    )
                    continue
                if value_payload is None:
                    frame.record(
                        StructuralDirective(
                            name=key,
                            line=line_number,
                            certainty=EvidenceCertainty.AMBIGUOUS,
                        )
                    )
                    frame.invalidate(key)
                    if frame.audited_section == "system global" and key == "hostname":
                        hostname = None
                        hostname_proven = False
                    continue
                if key in frame.values or key in frame.uncertain_keys:
                    raise ValueError("duplicate directive in audited entry")

                value_tokens = _tokens(value_payload, f"invalid {key} value")
                if frame.audited_section == "system global" and key == "hostname":
                    if len(value_tokens) != 1:
                        raise ValueError("invalid hostname value")
                    raw_hostname = value_tokens[0]
                    normalized_hostname = raw_hostname.strip()
                    is_explicit_failure = normalized_hostname.casefold() in {"", "fortigate"}
                    if not is_explicit_failure and (
                        raw_hostname != normalized_hostname
                        or _HOSTNAME.fullmatch(normalized_hostname) is None
                    ):
                        raise ValueError("invalid hostname value")
                    hostname = normalized_hostname
                    hostname_proven = True
                elif frame.audited_section == "system interface" and key == "allowaccess":
                    lowered = set(map(str.lower, value_tokens))
                    contains_whitespace = any(
                        any(character.isspace() for character in token) for token in value_tokens
                    )
                    if contains_whitespace:
                        frame.record(
                            StructuralDirective(
                                name=key,
                                tokens=tuple(value_tokens),
                                line=line_number,
                                certainty=EvidenceCertainty.AMBIGUOUS,
                            )
                        )
                        frame.invalidate(key)
                        continue
                    if not lowered <= _SUPPORTED_ALLOWACCESS:
                        frame.record(
                            StructuralDirective(
                                name=key,
                                tokens=tuple(value_tokens),
                                line=line_number,
                                certainty=EvidenceCertainty.AMBIGUOUS,
                            )
                        )
                        frame.invalidate(key)
                        continue
                elif (frame.audited_section == "system interface" and key == "role") or (
                    frame.audited_section == "system admin" and key == "two-factor"
                ):
                    if len(value_tokens) != 1:
                        frame.record(
                            StructuralDirective(
                                name=key,
                                tokens=tuple(value_tokens),
                                line=line_number,
                                certainty=EvidenceCertainty.AMBIGUOUS,
                            )
                        )
                        frame.invalidate(key)
                        continue
                elif frame.audited_section == "system admin" and key == "peer-auth":
                    if len(value_tokens) != 1 or value_tokens[0].casefold() not in {
                        "enable",
                        "disable",
                    }:
                        frame.record(
                            StructuralDirective(
                                name=key,
                                tokens=tuple(value_tokens),
                                line=line_number,
                                certainty=EvidenceCertainty.AMBIGUOUS,
                            )
                        )
                        frame.invalidate(key)
                        continue
                frame.record(
                    StructuralDirective(
                        name=key,
                        tokens=tuple(value_tokens),
                        line=line_number,
                    )
                )
                frame.values[key] = " ".join(value_tokens)
                continue

            if keyword in _MUTATION_DIRECTIVES and stack:
                frame = stack[-1]
                if frame.audited_section is None:
                    try:
                        mutation_payload = _payload(line, keyword, "malformed mutation directive")
                        mutation_tokens = tuple(
                            _tokens(mutation_payload, "malformed mutation directive")
                        )
                        mutation_name = mutation_tokens[0].lower()
                    except ValueError:
                        frame.mark_ambiguous()
                        frame.invalidate("<malformed>")
                        frame.record(
                            StructuralDirective(
                                name=keyword,
                                line=line_number,
                                certainty=EvidenceCertainty.AMBIGUOUS,
                                mutation=True,
                            )
                        )
                    else:
                        frame.invalidate(mutation_name)
                        frame.record(
                            StructuralDirective(
                                name=mutation_name,
                                tokens=mutation_tokens[1:],
                                line=line_number,
                                mutation=True,
                            )
                        )
                    continue
                if frame.audited_section in _AUDITED_ENTRY_SECTIONS and frame.entry_name is None:
                    raise ValueError("directive outside audited entry")
                mutation_payload = _payload(line, keyword, "malformed mutation directive")
                mutation_tokens = _tokens(mutation_payload, "malformed mutation directive")
                key = mutation_tokens[0].lower()
                frame.record(
                    StructuralDirective(
                        name=key,
                        tokens=tuple(mutation_tokens[1:]),
                        line=line_number,
                        mutation=True,
                        certainty=EvidenceCertainty.AMBIGUOUS,
                    )
                )
                frame.mark_ambiguous()
                if key in _RELEVANT_KEYS[frame.audited_section]:
                    frame.invalidate(key)
                    if frame.audited_section == "system global" and key == "hostname":
                        hostname = None
                        hostname_proven = False
                continue

            if not stack:
                if not saw_configuration:
                    raise ValueError("Aucun parseur compatible trouvé")
                raise ValueError(f"content outside configuration block at line {line_number}")
            # Other directives are deliberately ignored semantically. Preserve
            # their shape in the structural document, but make case/keyword
            # transformations non-probative in audited sections.
            if stack[-1].audited_section is not None:
                frame = stack[-1]
                audited_section = frame.audited_section
                assert audited_section is not None
                frame.mark_ambiguous()
                if audited_section == "system global":
                    hostname_proven = False
                frame.record(
                    StructuralDirective(
                        name=normalized_keyword,
                        tokens=_best_effort_tokens(line.partition(" ")[2] or None),
                        line=line_number,
                    )
                )

        if stack or not saw_configuration:
            raise ValueError("unsupported or incomplete FortiGate configuration")

        sections = tuple(_structural_section(frame) for frame in top_level_frames)
        document = StructuralDocument(sections=sections)
        zones, policies, local_users, security_profiles = _project_generic_sections(document)
        firewall_projection = project_firewall(document)
        object_references = tuple(
            reference
            for policy in policies
            for reference in policy.object_references
        )
        device_identity = DeviceIdentity(
            hostname=hostname,
            model=identity_model,
            firmware_version=firmware_version,
            parsed_keys=frozenset(
                identity_keys | ({"hostname"} if hostname_proven else set())
            ),
            proof_state=(
                ProofState.PROVEN
                if hostname_proven or identity_keys
                else ProofState.UNKNOWN
            ),
        )
        configuration = FortiGateConfiguration(
            hostname=hostname,
            device_identity=device_identity,
            interfaces=tuple(interfaces),
            zones=zones,
            policies=policies,
            object_references=object_references,
            administrators=tuple(administrators),
            local_users=local_users,
            security_profiles=security_profiles,
            document=document,
            parsed_sections=frozenset(parsed_sections),
            parsed_entry_sections=frozenset(parsed_entry_sections),
            parsed_value_sections=frozenset({"system global"} if hostname_proven else set()),
        )
        configuration = apply_firewall_projection(configuration, firewall_projection)
        configuration = apply_vpn_projection(configuration, project_vpn(document))
        return apply_utm_projection(configuration, project_utm(document))
