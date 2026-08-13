import re
import unicodedata
from dataclasses import dataclass, field

from vysion.audit.models import Administrator, FortiGateConfiguration, Interface

_AUDITED_ENTRY_SECTIONS = {"system interface", "system admin"}
_AUDITED_SECTIONS = _AUDITED_ENTRY_SECTIONS | {"system global"}
_ALLOWED_CONTROLS = {"\n", "\r", "\t"}
_RELEVANT_KEYS = {
    "system global": {"hostname"},
    "system interface": {"ip", "allowaccess", "role"},
    "system admin": {"two-factor"},
}
_MUTATION_DIRECTIVES = {"append", "select", "unselect", "unset"}
_RESERVED_DIRECTIVES = _MUTATION_DIRECTIVES | {"config", "edit", "end", "next", "set"}
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
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z"
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


@dataclass
class _Frame:
    section: str
    audited_section: str | None
    entry_name: str | None = None
    values: dict[str, str] = field(default_factory=dict)
    uncertain_keys: set[str] = field(default_factory=set)

    def invalidate(self, key: str) -> None:
        self.values.pop(key, None)
        self.uncertain_keys.add(key)


class FortiGateParser:
    def parse(self, raw: str) -> FortiGateConfiguration:
        raw = raw.removeprefix("\ufeff")
        _reject_dangerous_characters(raw)

        hostname: str | None = None
        hostname_proven = False
        interfaces: list[Interface] = []
        administrators: list[Administrator] = []
        parsed_sections: set[str] = set()
        parsed_entry_sections: set[str] = set()
        stack: list[_Frame] = []
        saw_configuration = False

        def flush_entry(frame: _Frame) -> None:
            if frame.entry_name is None:
                return
            if frame.audited_section == "system interface":
                parsed_entry_sections.add(frame.audited_section)
                interfaces.append(
                    Interface(
                        name=frame.entry_name,
                        address=frame.values.get("ip"),
                        allowaccess=frozenset(frame.values.get("allowaccess", "").lower().split()),
                        role=frame.values.get("role", "").lower() or None,
                        parsed_keys=frozenset(frame.values),
                    )
                )
            elif frame.audited_section == "system admin":
                parsed_entry_sections.add(frame.audited_section)
                administrators.append(
                    Administrator(
                        name=frame.entry_name,
                        two_factor=frame.values.get("two-factor", "").lower() or None,
                        parsed_keys=frozenset(frame.values),
                    )
                )
            frame.entry_name = None
            frame.values = {}
            frame.uncertain_keys = set()

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
                section = " ".join(" ".join(config_tokens).split()).lower()
                is_top_level = not stack
                compact_section = _SECTION_SEPARATORS.sub("", section)
                resembles_audited = any(
                    section.startswith(audited)
                    or compact_section.startswith(_SECTION_SEPARATORS.sub("", audited))
                    for audited in _AUDITED_SECTIONS
                )
                if resembles_audited and (not is_top_level or section not in _AUDITED_SECTIONS):
                    raise ValueError("ambiguous or nested audited section")
                audited_section = section if is_top_level and section in _AUDITED_SECTIONS else None
                if audited_section is not None and audited_section in parsed_sections:
                    raise ValueError("duplicate audited section")
                stack.append(_Frame(section=section, audited_section=audited_section))
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
                if stack[-1].audited_section is None:
                    stack[-1].entry_name = "<ignored>"
                else:
                    edit_tokens = _tokens(edit_payload, "malformed edit directive")
                    if len(edit_tokens) != 1:
                        raise ValueError("malformed edit directive")
                    stack[-1].entry_name = edit_tokens[0]
                stack[-1].values = {}
                stack[-1].uncertain_keys = set()
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
                    continue
                if frame.audited_section in _AUDITED_ENTRY_SECTIONS and frame.entry_name is None:
                    raise ValueError("directive outside audited entry")

                payload = _payload(line, "set", "malformed set directive")
                key, value_payload = _key_and_value(payload, "malformed set directive")
                if key not in _RELEVANT_KEYS[frame.audited_section]:
                    continue
                if value_payload is None:
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
                        frame.invalidate(key)
                        continue
                    if not lowered <= _SUPPORTED_ALLOWACCESS:
                        frame.invalidate(key)
                        continue
                elif (frame.audited_section == "system interface" and key == "role") or (
                    frame.audited_section == "system admin" and key == "two-factor"
                ):
                    if len(value_tokens) != 1:
                        frame.invalidate(key)
                        continue
                frame.values[key] = " ".join(value_tokens)
                continue

            if keyword in _MUTATION_DIRECTIVES and stack:
                frame = stack[-1]
                if frame.audited_section is None:
                    continue
                if frame.audited_section in _AUDITED_ENTRY_SECTIONS and frame.entry_name is None:
                    raise ValueError("directive outside audited entry")
                mutation_payload = _payload(line, keyword, "malformed mutation directive")
                mutation_tokens = _tokens(mutation_payload, "malformed mutation directive")
                if mutation_tokens:
                    key = mutation_tokens[0].lower()
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
            # Other directives are deliberately ignored and never become evidence.

        if stack or not saw_configuration:
            raise ValueError("unsupported or incomplete FortiGate configuration")
        return FortiGateConfiguration(
            hostname=hostname,
            interfaces=tuple(interfaces),
            administrators=tuple(administrators),
            parsed_sections=frozenset(parsed_sections),
            parsed_entry_sections=frozenset(parsed_entry_sections),
            parsed_value_sections=frozenset({"system global"} if hostname_proven else set()),
        )
