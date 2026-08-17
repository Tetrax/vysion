import re
import unicodedata
from dataclasses import dataclass, field

from vysion.audit.firewall_projection import apply_firewall_projection, project_firewall
from vysion.audit.ha_projection import apply_ha_projection, project_ha
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
_CASEFOLD_UNIQUE_ENTRY_SECTIONS = {
    "system zone",
    "system sdwan",
    "zone",
    "members",
    "user local",
    "user ldap",
    "vpn ipsec phase1-interface",
    "vpn ipsec phase2-interface",
}
_ALLOWED_CONTROLS = {"\n", "\r", "\t"}
_RELEVANT_KEYS = {
    "system global": {
        "hostname",
        "revision-backup-on-logout",
        "revision-image-auto-backup",
        "default-voip-alg-mode",
    },
    "system interface": {"ip", "allowaccess", "role"},
    "system admin": {"peer-auth", "two-factor"},
}
_TOLERATED_NON_PROBATIVE_KEYS = {
    "system global": {
        "admin-server-cert",
        "admin-sport",
        "admintimeout",
        "alias",
        "allow-traffic-redirect",
        "cli-audit-log",
        "fortitoken-cloud-region",
        "gui-auto-upgrade-setup-warning",
        "gui-certificates",
        "gui-display-hostname",
        "gui-replacement-message-groups",
        "gui-wireless-opensecurity",
        "ipv6-allow-traffic-redirect",
        "ldapconntimeout",
        "management-ip",
        "remoteauthtimeout",
        "reset-sessionless-tcp",
        "rest-api-key-url-query",
        "revision-backup-on-logout",
        "revision-image-auto-backup",
        "sslvpn-web-mode",
        "strict-dirty-session-check",
        "switch-controller",
        "timezone",
        "virtual-switch-vlan",
    },
    "system interface": {
        "alias",
        "broadcast-forward",
        "color",
        "defaultgw",
        "description",
        "device-identification",
        "dhcp-relay-ip",
        "dhcp-relay-service",
        "estimated-downstream-bandwidth",
        "estimated-upstream-bandwidth",
        "explicit-web-proxy",
        "interface",
        "ip-managed-by-fortiipam",
        "member",
        "mode",
        "monitor-bandwidth",
        "mtu",
        "mtu-override",
        "netflow-sampler",
        "remote-ip",
        "replacemsg-override-group",
        "secondary-ip",
        "security-mode",
        "snmp-index",
        "src-check",
        "status",
        "tcp-mss",
        "type",
        "vdom",
        "vlanforward",
        "vlanid",
    },
    "system admin": {
        "accprofile",
        "email-to",
        "gui-default-dashboard-template",
        "gui-ignore-release-overview-version",
        "old-password",
        "password",
        "peer-group",
        "trusthost1",
        "vdom",
    },
}
_TOLERATED_CHILD_SECTIONS = {
    "system global": frozenset(),
    "system interface": frozenset({"secondaryip"}),
    "system admin": frozenset({"dashboard", "gui-dashboard"}),
}
_MUTATION_DIRECTIVES = {"append", "select", "unselect", "unset"}
_RESERVED_DIRECTIVES = _MUTATION_DIRECTIVES | {"config", "edit", "end", "next", "set"}
_PROJECTED_SECTIONS = {
    "system zone",
    "system sdwan",
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
    "system ha",
}
_PROJECTED_KEYS = {
    "system zone": {"interface"},
    "system sdwan": {"interface", "member"},
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
    "firewall service custom": {
        "tcp-portrange",
        "udp-portrange",
        "member",
        "protocol",
        "protocol-number",
    },
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
    "system ha": {
        "group-name",
        "session-pickup",
        "session-pickup-connectionless",
        "session-pickup-expectation",
        "hbdev",
        "override",
        "override-wait-time",
    },
}
_PROJECTED_TOLERATED_NON_PROBATIVE_KEYS = {
    "system zone": frozenset({"intrazone"}),
    "system sdwan": frozenset({"status", "load-balance-mode", "duplicate"}),
    "firewall policy": frozenset(
        {
            "auto-asic-offload",
            "comment",
            "comments",
            "disclaimer",
            "dlp-profile",
            "dstaddr-negate",
            "emailfilter-profile",
            "fsso-groups",
            "global-label",
            "groups",
            "inspection-mode",
            "internet-service-src",
            "ippool",
            "label",
            "logtraffic-start",
            "match-vip",
            "nat",
            "np-acceleration",
            "per-ip-shaper",
            "poolname",
            "profile-protocol-options",
            "session-ttl",
            "tcp-mss-receiver",
            "tcp-mss-sender",
            "users",
            "uuid",
        }
    ),
    "firewall service custom": frozenset(
        {
            "category",
            "comment",
            "icmpcode",
            "icmptype",
            "proxy",
            "uuid",
        }
    ),
    "firewall service group": frozenset({"comment", "uuid"}),
    "firewall vip": frozenset(
        {"comment", "extport", "mappedport", "portforward", "protocol", "uuid"}
    ),
    "firewall vipgrp": frozenset({"interface", "uuid"}),
    "user local": frozenset({"passwd", "passwd-time"}),
    "user ldap": frozenset(
        {
            "cnid",
            "dn",
            "password",
            "password-expiry-warning",
            "password-renewal",
            "port",
            "server",
            "server-identity-check",
            "source-ip",
            "type",
            "username",
        }
    ),
    "vpn ssl settings": frozenset(
        {
            "algorithm",
            "auth-timeout",
            "banned-cipher",
            "default-portal",
            "dns-server1",
            "dns-server2",
            "dns-suffix",
            "idle-timeout",
            "port",
            "servercert",
            "source-address",
            "source-address6",
            "ssl-min-proto-ver",
            "tunnel-ip-pools",
        }
    ),
    "vpn ipsec phase1-interface": frozenset(
        {
            "add-route",
            "comments",
            "dpd",
            "dpd-retryinterval",
            "keylife",
            "local-gw",
            "localid",
            "mode",
            "nattraversal",
            "net-device",
            "npu-offload",
            "peerid",
            "peertype",
            "psksecret",
            "remote-gw",
            "remotegw-ddns",
            "type",
        }
    ),
    "vpn ipsec phase2-interface": frozenset(
        {
            "auto-negotiate",
            "dst-addr-type",
            "dst-name",
            "dst-start-ip",
            "dst-subnet",
            "keepalive",
            "keylifeseconds",
            "route-overlap",
            "src-addr-type",
            "src-name",
            "src-subnet",
        }
    ),
    "system ha": frozenset(
        {
            "group-id",
            "hb-interval",
            "hb-lost-threshold",
            "mode",
            "monitor",
            "password",
            "priority",
            "route-hold",
            "route-ttl",
            "route-wait",
            "sync-config",
            "unicast-hb",
            "unicast-hb-peerip",
        }
    ),
}
_PROJECTED_CHILD_KEYS = {
    "zone": {"interface", "member"},
    "members": {"interface", "zone"},
    "health-check": {
        "server",
        "members",
        "interval",
        "failtime",
        "recoverytime",
        "update-cascade-interface",
        "sla-fail-log-period",
        "sla-pass-log-period",
        "http-agent",
        "protocol",
        "port",
    },
    "service": {
        "name",
        "mode",
        "dst",
        "src",
        "health-check",
        "priority-members",
        "quality",
    },
    "secondaryip": {"ip", "allowaccess"},
    "dashboard": {"name"},
    "realservers": {"ip", "port"},
    "web": {"blocklist"},
    "ftgd-wf": {"options"},
    "ftgd-dns": {"options"},
    "filters": {"category", "action"},
    "entries": {"category", "action"},
    "authentication-rule": {"groups", "portal"},
}
_PROJECTED_CHILDREN = {
    "system sdwan": frozenset({"zone", "members", "health-check", "service"}),
    "system interface": frozenset({"secondaryip"}),
    "system admin": frozenset({"dashboard", "gui-dashboard"}),
    "vpn ssl settings": frozenset({"authentication-rule"}),
    "firewall vip": frozenset({"realservers"}),
    "webfilter profile": frozenset({"web", "ftgd-wf"}),
    "dnsfilter profile": frozenset({"ftgd-dns"}),
    "application list": frozenset({"entries"}),
    "ftgd-wf": frozenset({"filters"}),
    "ftgd-dns": frozenset({"filters"}),
    "secondaryip": frozenset(),
    "dashboard": frozenset({"widget"}),
    "gui-dashboard": frozenset({"widget"}),
    "widget": frozenset(),
    "realservers": frozenset(),
    "web": frozenset(),
    "filters": frozenset(),
    "entries": frozenset(),
    "authentication-rule": frozenset(),
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
_FORTIOS_CANONICAL_KEY_FORMS = {
    "system interface": {"secondary-ip": "secondary-IP"},
}
_CERTAIN_UNSET_KEYS = {
    "application list": frozenset({"options"}),
    "cifs": frozenset({"options"}),
    "firewall service custom": frozenset(
        {"icmpcode", "icmptype", "tcp-portrange", "udp-portrange"}
    ),
    "ftgd-wf": frozenset({"options"}),
    "http": frozenset({"options", "post-lang"}),
    "nntp": frozenset({"options"}),
    "ssh": frozenset({"options"}),
}
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
_BACKUP_MARKERS = {
    "#buildno=": re.compile(r"#buildno=[0-9]+\Z"),
    "#global_vdom=": re.compile(r"#global_vdom=[0-9]+\Z"),
    "#conf_file_ver=": re.compile(r"#conf_file_ver=[0-9]+\Z"),
}


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


def _logical_lines(raw: str) -> tuple[tuple[int, str], ...]:
    """Join FortiOS physical lines while a double-quoted value remains open."""

    logical: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    quoted = False
    for line_number, physical_line in enumerate(raw.splitlines(), start=1):
        if not buffer:
            start_line = line_number
        buffer.append(physical_line)
        escaped = False
        for character in physical_line:
            if escaped:
                escaped = False
                continue
            if quoted and character == "\\":
                escaped = True
                continue
            if character == '"':
                quoted = not quoted
        if not quoted:
            logical.append((start_line, "\n".join(buffer)))
            buffer = []
    if buffer:
        logical.append((start_line, "\n".join(buffer)))
    return tuple(logical)


def _tokens(payload: str, error: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(payload):
        while position < len(payload) and payload[position].isspace():
            position += 1
        if position == len(payload):
            break
        if payload[position] == '"':
            position += 1
            token: list[str] = []
            while position < len(payload) and payload[position] != '"':
                if payload[position] == "\\":
                    if (
                        position + 1 < len(payload)
                        and payload[position + 1] in {'"', "\\"}
                    ):
                        token.append(payload[position + 1])
                        position += 2
                        continue
                    token.append("\\")
                    position += 1
                    continue
                token.append(payload[position])
                position += 1
            if position == len(payload):
                raise ValueError(error)
            tokens.append("".join(token))
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


def _is_canonical_key_form(section: str, raw_key: str, normalized_key: str) -> bool:
    if raw_key == normalized_key:
        return True
    return (
        _FORTIOS_CANONICAL_KEY_FORMS.get(section, {}).get(normalized_key) == raw_key
    )


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

    def record_certain_unset(self, key: str, line: int) -> None:
        directives = self.directives if self.entry_name is None else self.entry_directives
        directives[:] = [directive for directive in directives if directive.name != key]
        self.values.pop(key, None)
        self.uncertain_keys.discard(key)
        self.entry_structural_keys.discard(key)
        directives.append(StructuralDirective(name=key, line=line, mutation=True))

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
    casefold_entries = frame.section in _CASEFOLD_UNIQUE_ENTRY_SECTIONS
    for entry in frame.entries:
        key = entry.name.casefold() if casefold_entries else entry.name
        entry_counts[key] = entry_counts.get(key, 0) + 1
    entries: list[StructuralEntry] = []
    for entry in frame.entries:
        entry_key = entry.name.casefold() if casefold_entries else entry.name
        if entry_counts[entry_key] > 1:
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
    allowed_keys = _PROJECTED_KEYS.get(section_name) or _PROJECTED_CHILD_KEYS.get(
        section_name, frozenset()
    )
    return {
        name: directive
        for name, directive in _directive_map(entry).items()
        if name in allowed_keys
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


def _interface_references_are_proven(
    references: tuple[ObjectReference, ...],
    interface_names: frozenset[str],
) -> bool:
    normalized_names = tuple(reference.name.casefold() for reference in references)
    return bool(normalized_names) and len(set(normalized_names)) == len(
        normalized_names
    ) and all(name in interface_names for name in normalized_names)


def _project_generic_sections(
    document: StructuralDocument,
    interface_names: frozenset[str] = frozenset(),
) -> tuple[
    tuple[Zone, ...],
    tuple[Zone, ...],
    tuple[Policy, ...],
    tuple[LocalUser, ...],
    tuple[SecurityProfile, ...],
]:
    zones: list[Zone] = []
    sdwan_zones: list[Zone] = []
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
                references = (
                    _references(tuple(interface.tokens), "zone-interface", "interface")
                    if interface is not None
                    else ()
                )
                zones.append(
                    Zone(
                        name=entry.name,
                        interfaces=references,
                        parsed_keys=frozenset(directives),
                        proof_state=(
                            ProofState.PROVEN
                            if _interface_references_are_proven(references, interface_names)
                            and section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            else ProofState.UNKNOWN
                        ),
                    )
                )
        elif section.name == "system sdwan":
            nested_zone_section = next(
                (child for child in section.children if child.name == "zone"),
                None,
            )
            nested_members_section = next(
                (child for child in section.children if child.name == "members"),
                None,
            )
            if nested_zone_section is not None:
                nested_children_are_known = all(
                    child.name in {"zone", "members"} for child in section.children
                )
                member_references: dict[str, list[ObjectReference]] = {}
                member_certainty: dict[str, bool] = {}
                declared_zone_names = tuple(
                    entry.name.casefold() for entry in nested_zone_section.entries
                )
                if nested_members_section is not None:
                    for member in nested_members_section.entries:
                        directives = _projection_directives(member, "members")
                        interface = directives.get("interface")
                        zone = directives.get("zone")
                        zone_names = (
                            tuple(token.casefold() for token in zone.tokens)
                            if zone is not None
                            else declared_zone_names if len(declared_zone_names) == 1 else ()
                        )
                        if len(zone_names) != 1:
                            for zone_name in zone_names:
                                member_certainty[zone_name] = False
                            continue
                        zone_name = zone_names[0]
                        valid_member = (
                            interface is not None
                            and len(interface.tokens) == 1
                            and not member.children
                            and not nested_members_section.children
                            and nested_members_section.certainty
                            is EvidenceCertainty.CERTAIN
                            and member.certainty is EvidenceCertainty.CERTAIN
                        )
                        member_certainty[zone_name] = member_certainty.get(
                            zone_name, True
                        ) and valid_member
                        if interface is not None:
                            member_references.setdefault(zone_name, []).extend(
                                _references(
                                    tuple(interface.tokens),
                                    "sdwan-member",
                                    "interface",
                                )
                            )
                for entry in nested_zone_section.entries:
                    directives = _projection_directives(entry, "zone")
                    direct_interface = directives.get("interface")
                    direct_member = directives.get("member")
                    direct_selected = direct_interface or direct_member
                    direct_aliases_are_unambiguous = not (
                        direct_interface is not None and direct_member is not None
                    )
                    direct_references = (
                        _references(
                            tuple(direct_selected.tokens),
                            "sdwan-interface",
                            "interface",
                        )
                        if direct_selected is not None
                        else ()
                    )
                    references = direct_references + tuple(
                        member_references.get(entry.name.casefold(), ())
                    )
                    has_members = nested_members_section is not None
                    references_are_proven = _interface_references_are_proven(
                        references, interface_names
                    )
                    evidence_is_complete = (
                        member_certainty.get(entry.name.casefold(), False)
                        if has_members
                        else bool(direct_references)
                    )
                    sdwan_zones.append(
                        Zone(
                            name=entry.name,
                            interfaces=references,
                            parsed_keys=frozenset(directives)
                            | (
                                {"interface"}
                                if member_references.get(entry.name.casefold())
                                else set()
                            ),
                            proof_state=(
                                ProofState.PROVEN
                                if nested_children_are_known
                                and not entry.children
                                and direct_aliases_are_unambiguous
                                and evidence_is_complete
                                and references_are_proven
                                and section.certainty is EvidenceCertainty.CERTAIN
                                and nested_zone_section.certainty
                                is EvidenceCertainty.CERTAIN
                                and entry.certainty is EvidenceCertainty.CERTAIN
                                else ProofState.UNKNOWN
                            ),
                        )
                    )
            else:
                for entry in section.entries:
                    directives = _projection_directives(entry, section.name)
                    interface = directives.get("interface")
                    member = directives.get("member")
                    selected = interface or member
                    aliases_are_unambiguous = (interface is None) != (member is None)
                    references = (
                        _references(tuple(selected.tokens), "sdwan-interface", "interface")
                        if selected is not None
                        else ()
                    )
                    sdwan_zones.append(
                        Zone(
                            name=entry.name,
                            interfaces=references,
                            parsed_keys=frozenset(directives),
                            proof_state=(
                                ProofState.PROVEN
                                if aliases_are_unambiguous
                                and not entry.children
                                and _interface_references_are_proven(references, interface_names)
                                and section.certainty is EvidenceCertainty.CERTAIN
                                and entry.certainty is EvidenceCertainty.CERTAIN
                                else ProofState.UNKNOWN
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
                        defaulted_keys=frozenset(
                            name for name, directive in directives.items() if directive.defaulted
                        ),
                        proof_state=(
                            ProofState.PROVEN
                            if srcintf is not None
                            and dstintf is not None
                            and srcaddr is not None
                            and dstaddr is not None
                            and section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
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
                        defaulted_keys=frozenset(
                            name for name, directive in directives.items() if directive.defaulted
                        ),
                        proof_state=(
                            ProofState.PROVEN
                            if directives
                            and section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            else ProofState.UNKNOWN
                        ),
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
                            and section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            else ProofState.UNKNOWN
                        ),
                    )
                )
    return (
        tuple(zones),
        tuple(sdwan_zones),
        tuple(policies),
        tuple(local_users),
        tuple(security_profiles),
    )


def _attach_interface_zones(
    interfaces: tuple[Interface, ...],
    zones: tuple[Zone, ...],
) -> tuple[Interface, ...]:
    """Attach only one certain zone relation to each interface."""
    return tuple(
        interface.model_copy(
            update={
                "zone": (
                    ObjectReference(
                        object_type="zone",
                        name=matches[0].name,
                        relation="member-of",
                    )
                    if len(matches) == 1
                    else None
                )
            }
        )
        for interface in interfaces
        for matches in [
            [
                zone
                for zone in zones
                if zone.proof_state is ProofState.PROVEN
                and any(
                    reference.name.casefold() == interface.name.casefold()
                    for reference in zone.interfaces
                )
            ]
        ]
    )


def _merge_repeated_projected_sections(
    sections: tuple[StructuralSection, ...],
) -> tuple[StructuralSection, ...]:
    """Merge only repeated entry namespaces whose object names are disjoint.

    FortiOS can emit the same projected namespace in separate blocks.  Flat
    settings and colliding object names cannot be combined without inventing
    precedence, so those repetitions remain present but explicitly ambiguous.
    """

    merged: list[StructuralSection] = []
    positions: dict[str, int] = {}
    for section in sections:
        if section.name not in _PROJECTED_SECTIONS or section.name not in positions:
            positions.setdefault(section.name, len(merged))
            merged.append(section)
            continue
        position = positions[section.name]
        previous = merged[position]
        previous_names = {entry.name.casefold() for entry in previous.entries}
        current_names = {entry.name.casefold() for entry in section.entries}
        safely_disjoint = bool(previous.entries and section.entries) and previous_names.isdisjoint(
            current_names
        )
        if safely_disjoint:
            merged[position] = previous.model_copy(
                update={
                    "entries": previous.entries + section.entries,
                    "directives": previous.directives + section.directives,
                    "children": previous.children + section.children,
                    "parsed_keys": previous.parsed_keys | section.parsed_keys,
                    "invalidated_keys": previous.invalidated_keys | section.invalidated_keys,
                    "certainty": (
                        EvidenceCertainty.CERTAIN
                        if previous.certainty is EvidenceCertainty.CERTAIN
                        and section.certainty is EvidenceCertainty.CERTAIN
                        else EvidenceCertainty.AMBIGUOUS
                    ),
                }
            )
            continue
        ambiguous = EvidenceCertainty.AMBIGUOUS
        merged[position] = previous.model_copy(
            update={
                "directives": previous.directives + section.directives,
                "entries": tuple(
                    entry.model_copy(update={"certainty": ambiguous})
                    for entry in previous.entries + section.entries
                ),
                "children": previous.children + section.children,
                "parsed_keys": previous.parsed_keys | section.parsed_keys,
                "invalidated_keys": previous.invalidated_keys | section.invalidated_keys,
                "certainty": ambiguous,
            }
        )
    return tuple(merged)


def _project_single_vdom(
    sections: tuple[StructuralSection, ...],
) -> tuple[tuple[StructuralSection, ...], bool]:
    """Project one explicit VDOM; keep multi-VDOM content structural-only.

    The boolean tells the caller whether backup-wide absence/default proofs are
    still valid.  With several VDOMs no scope was selected, so no child is
    flattened and controls must remain fail-closed instead of mixing tenants.
    """

    vdom_sections = tuple(section for section in sections if section.name == "vdom")
    if not vdom_sections:
        return sections, True
    entries = tuple(entry for section in vdom_sections for entry in section.entries)
    non_vdom = tuple(section for section in sections if section.name != "vdom")
    if (
        len(vdom_sections) == 1
        and len(entries) == 1
        and vdom_sections[0].certainty is EvidenceCertainty.CERTAIN
        and entries[0].certainty is EvidenceCertainty.CERTAIN
    ):
        return non_vdom + entries[0].children, True
    ambiguous = EvidenceCertainty.AMBIGUOUS
    scoped_sections = tuple(
        section
        if section.name == "vdom"
        else section.model_copy(
            update={
                "certainty": ambiguous,
                "entries": tuple(
                    entry.model_copy(update={"certainty": ambiguous})
                    for entry in section.entries
                ),
            }
        )
        for section in sections
    )
    return scoped_sections, False


_DOCUMENTED_FORTIOS_DEFAULTS: dict[str, dict[str, tuple[str, ...]]] = {
    "firewall policy": {"status": ("enable",)},
    "system admin": {"two-factor": ("disable",), "peer-auth": ("disable",)},
    "user local": {"two-factor": ("disable",)},
    "vpn ssl settings": {"status": ("enable",)},
    "vpn ipsec phase1-interface": {"ike-version": ("1",), "dhgrp": ("14",)},
    "vpn ipsec phase2-interface": {"pfs": ("enable",), "dhgrp": ("14",)},
}
_DEFAULTED_ENTRY_SECTIONS = frozenset(
    {
        "firewall policy",
        "system admin",
        "user local",
        "vpn ipsec phase1-interface",
        "vpn ipsec phase2-interface",
    }
)


def _materialize_documented_defaults(
    document: StructuralDocument,
    firmware_version: str | None,
    complete_backup: bool,
) -> StructuralDocument:
    if (
        not complete_backup
        or firmware_version is None
        or not firmware_version.startswith(("7.2.", "7.4."))
    ):
        return document
    sections: list[StructuralSection] = []
    for section in document.sections:
        defaults = _DOCUMENTED_FORTIOS_DEFAULTS.get(section.name)
        if defaults is None or section.certainty is not EvidenceCertainty.CERTAIN:
            sections.append(section)
            continue
        if section.name in _DEFAULTED_ENTRY_SECTIONS:
            entries: list[StructuralEntry] = []
            for entry in section.entries:
                if entry.certainty is not EvidenceCertainty.CERTAIN:
                    entries.append(entry)
                    continue
                directives = list(entry.directives)
                names = {item.name for item in directives if not item.mutation}
                effective_keys = set(entry.parsed_keys)
                for name, tokens in defaults.items():
                    if name not in names and name not in entry.invalidated_keys:
                        directives.append(
                            StructuralDirective(
                                name=name,
                                tokens=tokens,
                                line=entry.line,
                                defaulted=True,
                            )
                        )
                        effective_keys.add(name)
                entries.append(
                    entry.model_copy(
                        update={
                            "directives": tuple(directives),
                            "parsed_keys": frozenset(effective_keys),
                        }
                    )
                )
            sections.append(section.model_copy(update={"entries": tuple(entries)}))
            continue
        directives = list(section.directives)
        names = {item.name for item in directives if not item.mutation}
        effective_keys = set(section.parsed_keys)
        for name, tokens in defaults.items():
            if name not in names and name not in section.invalidated_keys:
                directives.append(
                    StructuralDirective(
                        name=name,
                        tokens=tokens,
                        line=section.line,
                        defaulted=True,
                    )
                )
                effective_keys.add(name)
        sections.append(
            section.model_copy(
                update={
                    "directives": tuple(directives),
                    "parsed_keys": frozenset(effective_keys),
                }
            )
        )
    return document.model_copy(update={"sections": tuple(sections)})


class FortiGateParser:
    def parse(self, raw: str) -> FortiGateConfiguration:
        raw = raw.removeprefix("\ufeff")
        _reject_dangerous_characters(raw)

        config_headers = tuple(
            match
            for original_line in raw.splitlines()
            if (match := _CONFIG_VERSION.fullmatch(original_line.strip())) is not None
        )
        physical_lines = raw.splitlines()
        marker_prefixes = ("#config-version=", *_BACKUP_MARKERS)
        marker_counts = {
            prefix: sum(line.strip().startswith(prefix) for line in physical_lines)
            for prefix in marker_prefixes
        }
        first_config_line = next(
            (
                index
                for index, line in enumerate(physical_lines)
                if line.strip().startswith("config ")
            ),
            None,
        )
        markers_before_configuration = bool(
            first_config_line is not None
            and all(
                sum(
                    index < first_config_line and pattern.fullmatch(line.strip()) is not None
                    for index, line in enumerate(physical_lines)
                )
                == 1
                for pattern in _BACKUP_MARKERS.values()
            )
        )
        nonempty_lines = tuple(line.strip() for line in physical_lines if line.strip())
        complete_backup = bool(
            len(config_headers) == 1
            and nonempty_lines
            and nonempty_lines[0].startswith("#config-version=")
            and nonempty_lines[-1] == "end"
            and all(count == 1 for count in marker_counts.values())
            and markers_before_configuration
            and all(
                sum(pattern.fullmatch(line) is not None for line in nonempty_lines) == 1
                for pattern in _BACKUP_MARKERS.values()
            )
        )
        identity_model: str | None = None
        firmware_version: str | None = None
        identity_keys: set[str] = set()
        if len(config_headers) == 1:
            identity_model = config_headers[0].group("model")
            firmware_version = config_headers[0].group("version")
            identity_keys.update({"model", "firmware-version"})
        complete_backup = bool(
            complete_backup
            and firmware_version is not None
            and firmware_version.startswith(("7.2.", "7.4."))
        )

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
                not _is_canonical_key_form(frame.section, raw_key, key)
                or key not in projected_keys | tolerated_keys
            ):
                frame.mark_ambiguous()
            if frame.section in {"gui-dashboard", "widget"} and key in _RELEVANT_KEYS[
                "system admin"
            ]:
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

        for line_number, original_line in _logical_lines(raw):
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
                config_payload = _payload(line, "config", "malformed config directive")
                config_tokens = _tokens(
                    config_payload,
                    "malformed config directive",
                )
                raw_section = " ".join(" ".join(config_tokens).split())
                section = raw_section.lower()
                is_top_level = not stack
                nested_in_vdom = bool(
                    stack
                    and stack[0].section == "vdom"
                    and stack[0].entry_name is not None
                    and len(stack) == 1
                )
                if not is_top_level and section in _PROJECTED_SECTIONS and not nested_in_vdom:
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
                frame = _Frame(section=section, audited_section=audited_section, line=line_number)
                is_projected_shape = (
                    section in _AUDITED_SECTIONS
                    or section in _PROJECTED_SECTIONS
                    or section in _PROJECTED_CHILD_KEYS
                )
                if is_projected_shape and config_payload != section:
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
                canonical_key = _is_canonical_key_form(frame.section, raw_key, key)
                if not canonical_key:
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
                    hostname_proven = (
                        canonical_key and frame.certainty is EvidenceCertainty.CERTAIN
                    )
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
                        certainty=(
                            EvidenceCertainty.CERTAIN
                            if canonical_key
                            else EvidenceCertainty.AMBIGUOUS
                        ),
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
                        if (
                            keyword == "unset"
                            and len(mutation_tokens) == 1
                            and mutation_name in _CERTAIN_UNSET_KEYS.get(
                                frame.section, frozenset()
                            )
                            and _is_canonical_key_form(
                                frame.section, mutation_tokens[0], mutation_name
                            )
                        ):
                            frame.record_certain_unset(mutation_name, line_number)
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
                known_keys = (
                    _RELEVANT_KEYS[frame.audited_section]
                    | _TOLERATED_NON_PROBATIVE_KEYS[frame.audited_section]
                )
                if (
                    keyword == "unset"
                    and len(mutation_tokens) == 1
                    and key in known_keys
                    and _is_canonical_key_form(frame.section, mutation_tokens[0], key)
                ):
                    frame.record_certain_unset(key, line_number)
                    if frame.audited_section == "system global" and key == "hostname":
                        hostname = None
                        hostname_proven = False
                    continue
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
        sections, vdom_scope_is_complete = _project_single_vdom(sections)
        complete_backup = complete_backup and vdom_scope_is_complete
        sections = _merge_repeated_projected_sections(sections)
        document = StructuralDocument(sections=sections)
        document = _materialize_documented_defaults(
            document,
            firmware_version,
            complete_backup,
        )
        admin_section = document.section("system admin")
        if admin_section is not None:
            normalized_administrators: list[Administrator] = []
            for administrator in administrators:
                matches = tuple(
                    entry for entry in admin_section.entries if entry.name == administrator.name
                )
                if len(matches) != 1:
                    normalized_administrators.append(administrator)
                    continue
                entry = matches[0]
                directives = _directive_map(entry)
                two_factor = directives.get("two-factor")
                peer_auth = directives.get("peer-auth")
                normalized_administrators.append(
                    administrator.model_copy(
                        update={
                            "two_factor": (
                                two_factor.tokens[0].casefold()
                                if two_factor is not None and len(two_factor.tokens) == 1
                                else None
                            ),
                            "peer_auth": (
                                peer_auth.tokens[0].casefold() == "enable"
                                if peer_auth is not None
                                and len(peer_auth.tokens) == 1
                                and peer_auth.tokens[0].casefold() in _SUPPORTED_PEER_AUTH
                                else None
                            ),
                            "parsed_keys": frozenset(directives),
                            "defaulted_keys": frozenset(
                                name
                                for name, directive in directives.items()
                                if directive.defaulted
                            ),
                            "proof_state": (
                                ProofState.PROVEN
                                if entry.certainty is EvidenceCertainty.CERTAIN
                                and (two_factor is not None or peer_auth is not None)
                                else ProofState.UNKNOWN
                            ),
                        }
                    )
                )
            administrators = normalized_administrators
        (
            zones,
            sdwan_zones,
            policies,
            local_users,
            security_profiles,
        ) = _project_generic_sections(
            document,
            frozenset(interface.name.casefold() for interface in interfaces),
        )
        interfaces = list(_attach_interface_zones(tuple(interfaces), zones))
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
            complete_backup=complete_backup,
            device_identity=device_identity,
            interfaces=tuple(interfaces),
            zones=zones,
            sdwan_zones=sdwan_zones,
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
        configuration = apply_ha_projection(configuration, project_ha(document))
        return apply_utm_projection(configuration, project_utm(document))
