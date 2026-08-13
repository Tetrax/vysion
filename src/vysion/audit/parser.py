import re
from dataclasses import dataclass, field

from vysion.audit.models import Administrator, FortiGateConfiguration, Interface

_AUDITED_ENTRY_SECTIONS = {"system interface", "system admin"}
_AUDITED_TOP_LEVEL_SECTIONS = _AUDITED_ENTRY_SECTIONS | {"system global"}
_SUPPORTED_ENTRY_KEYS = {
    "system interface": {"ip", "allowaccess"},
    "system admin": {"two-factor"},
}
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
_SECTION_NAME = re.compile(r"[A-Za-z0-9-]+(?: [A-Za-z0-9-]+)*\Z")
_RESERVED_DIRECTIVES = {"config", "edit", "set", "next", "end"}


def _is_audited_section_lookalike(section: str) -> bool:
    words = section.split()
    if not words:
        return False
    if words[0] != "system" and words[0].startswith("system"):
        return True
    if words[0] != "system" or len(words) < 2:
        return False
    audited_leafs = {name.split()[1] for name in _AUDITED_TOP_LEVEL_SECTIONS}
    return any(
        words[1].startswith(leaf) and section != f"system {leaf}"
        for leaf in audited_leafs
    )


def _split_directive(line: str, keyword: str, error: str) -> list[str]:
    if not line.startswith(keyword) or len(line) == len(keyword):
        raise ValueError(error)
    payload = line[len(keyword) :]
    if not payload[0].isspace():
        raise ValueError(error)
    payload = payload.strip()
    if not payload or "'" in payload or "\\" in payload:
        raise ValueError(error)

    raw_tokens: list[str] = []
    position = 0
    while position < len(payload):
        if payload[position] == '"':
            position += 1
            start = position
            while position < len(payload) and payload[position] != '"':
                position += 1
            if position == len(payload):
                raise ValueError(error)
            raw_tokens.append(payload[start:position])
            position += 1
            if position < len(payload) and not payload[position].isspace():
                raise ValueError(error)
        else:
            start = position
            while position < len(payload) and not payload[position].isspace():
                if payload[position] == '"':
                    raise ValueError(error)
                position += 1
            raw_tokens.append(payload[start:position])
        while position < len(payload) and payload[position].isspace():
            position += 1

    return [keyword, *raw_tokens]


@dataclass
class _Frame:
    section: str
    entry_name: str | None = None
    values: dict[str, str] = field(default_factory=dict)


class FortiGateParser:
    def parse(self, raw: str) -> FortiGateConfiguration:
        if any(
            character not in {"\n", "\r", "\t"}
            and not 0x20 <= ord(character) <= 0x7E
            for character in raw
        ):
            raise ValueError("invalid character in configuration")
        hostname: str | None = None
        interfaces: list[Interface] = []
        administrators: list[Administrator] = []
        parsed_sections: set[str] = set()
        parsed_entry_sections: set[str] = set()
        parsed_value_sections: set[str] = set()
        stack: list[_Frame] = []

        def flush_entry(frame: _Frame) -> None:
            if frame.entry_name is None:
                return
            if len(stack) == 1:
                parsed_entry_sections.add(frame.section)
            if len(stack) == 1 and frame.section == "system interface":
                interfaces.append(
                    Interface(
                        name=frame.entry_name,
                        address=frame.values.get("ip"),
                        allowaccess=frozenset(frame.values.get("allowaccess", "").lower().split()),
                        parsed_keys=frozenset(frame.values),
                    )
                )
            elif len(stack) == 1 and frame.section == "system admin":
                administrators.append(
                    Administrator(
                        name=frame.entry_name,
                        two_factor=frame.values.get("two-factor", "").lower() or None,
                    )
                )
            frame.entry_name = None
            frame.values = {}

        for original_line in raw.splitlines():
            if original_line and original_line[-1] in {" ", "\t"}:
                raise ValueError("trailing whitespace in configuration")
            line = original_line.strip()
            if not line or line.startswith("#"):
                continue
            first_word = line.split(maxsplit=1)[0]
            if first_word not in _RESERVED_DIRECTIVES and (
                first_word.lower() in _RESERVED_DIRECTIVES
                or any(
                    first_word.lower().startswith(word)
                    for word in _RESERVED_DIRECTIVES
                )
            ):
                raise ValueError("malformed reserved directive")
            if line.split(maxsplit=1)[0] == "config":
                tokens = _split_directive(line, "config", "malformed config directive")
                section = " ".join(" ".join(tokens[1:]).split()).lower()
                if _SECTION_NAME.fullmatch(section) is None:
                    raise ValueError("invalid section name")
                if _is_audited_section_lookalike(section):
                    raise ValueError("malformed audited section")
                if stack:
                    if stack[-1].section == "system global":
                        raise ValueError("unsupported content in audited section")
                    if stack[-1].section in _AUDITED_ENTRY_SECTIONS:
                        scope = "entry" if stack[-1].entry_name is not None else "section"
                        raise ValueError(f"unsupported nested section in audited {scope}")
                    if section in _AUDITED_TOP_LEVEL_SECTIONS:
                        raise ValueError("audited section must be top-level")
                    raise ValueError("unsupported nested section")
                if not stack:
                    if section in _AUDITED_TOP_LEVEL_SECTIONS and section in parsed_sections:
                        raise ValueError("duplicate audited section")
                    parsed_sections.add(section)
                stack.append(_Frame(section=section))
                continue
            if line.split(maxsplit=1)[0] == "edit":
                if stack and stack[-1].section == "system global":
                    raise ValueError("unsupported content in audited section")
                if not stack or stack[-1].entry_name is not None:
                    raise ValueError("unsupported or incomplete FortiGate configuration")
                tokens = _split_directive(line, "edit", "malformed edit directive")
                if len(tokens) != 2 or tokens[0] != "edit" or not tokens[1].strip():
                    raise ValueError("malformed edit directive")
                stack[-1].entry_name = tokens[1]
                continue
            if line == "next":
                if not stack or stack[-1].entry_name is None:
                    raise ValueError("unsupported or incomplete FortiGate configuration")
                flush_entry(stack[-1])
                continue
            if line == "end":
                if not stack or stack[-1].entry_name is not None:
                    raise ValueError("unsupported or incomplete FortiGate configuration")
                stack.pop()
                continue
            if line.split(maxsplit=1)[0] == "set":
                tokens = _split_directive(line, "set", "malformed set directive")
                if len(tokens) < 3 or tokens[0] != "set" or not stack:
                    raise ValueError("malformed set directive")
                key = tokens[1].lower()
                value_tokens = tokens[2:]
                frame = stack[-1]
                if frame.section in _AUDITED_ENTRY_SECTIONS and frame.entry_name is None:
                    raise ValueError("set outside entry in audited section")
                if len(stack) == 1:
                    parsed_value_sections.add(frame.section)
                if frame.entry_name is not None and frame.section in _AUDITED_ENTRY_SECTIONS:
                    if key not in _SUPPORTED_ENTRY_KEYS[frame.section]:
                        raise ValueError("unsupported set key in audited entry")
                    if key in frame.values:
                        raise ValueError("duplicate directive in audited entry")
                    invalid_allowaccess = (
                        frame.section == "system interface"
                        and key == "allowaccess"
                        and any(
                            not token or any(char.isspace() for char in token)
                            for token in value_tokens
                        )
                    )
                    if invalid_allowaccess:
                        raise ValueError("invalid allowaccess value")
                    if (
                        frame.section == "system interface"
                        and key == "allowaccess"
                        and not set(map(str.lower, value_tokens)) <= _SUPPORTED_ALLOWACCESS
                    ):
                        raise ValueError("unsupported allowaccess value")
                    if (
                        frame.section == "system admin"
                        and key == "two-factor"
                        and len(value_tokens) != 1
                    ):
                        raise ValueError("invalid two-factor value")
                    frame.values[key] = " ".join(value_tokens)
                elif len(stack) == 1 and frame.section == "system global":
                    if key in frame.values:
                        raise ValueError("duplicate directive in audited section")
                    frame.values[key] = " ".join(value_tokens)
                    if key == "hostname":
                        if len(value_tokens) != 1:
                            raise ValueError("invalid hostname value")
                        raw_hostname = value_tokens[0]
                        normalized_hostname = raw_hostname.strip()
                        if (
                            raw_hostname != normalized_hostname
                            and normalized_hostname.casefold() not in {"", "fortigate"}
                        ):
                            raise ValueError("invalid hostname value")
                        if normalized_hostname and _HOSTNAME.fullmatch(normalized_hostname) is None:
                            raise ValueError("invalid hostname value")
                        hostname = normalized_hostname
                continue
            if not stack:
                if parsed_sections:
                    raise ValueError("content outside configuration block")
                raise ValueError("unsupported or incomplete FortiGate configuration")
            if len(stack) == 1 and stack[-1].section == "system global":
                raise ValueError("unsupported content in audited section")
            if (
                len(stack) == 1
                and stack[-1].section in _AUDITED_ENTRY_SECTIONS
                and stack[-1].entry_name is None
            ):
                raise ValueError("unsupported content in audited section")
            if (
                stack
                and stack[-1].entry_name is not None
                and stack[-1].section in _AUDITED_ENTRY_SECTIONS
            ):
                raise ValueError("unsupported directive in audited entry")

        if stack or not parsed_sections:
            raise ValueError("unsupported or incomplete FortiGate configuration")
        return FortiGateConfiguration(
            hostname=hostname,
            interfaces=tuple(interfaces),
            administrators=tuple(administrators),
            parsed_sections=frozenset(parsed_sections),
            parsed_entry_sections=frozenset(parsed_entry_sections),
            parsed_value_sections=frozenset(parsed_value_sections),
        )
