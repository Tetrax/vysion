import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

SYNTHETIC_CONFIG = """\
# Synthetic fixture created for Vysion v2
config system global
    set hostname "vysion-lab.example"
    set admin-sport 8443
end
config system interface
    edit "wan1"
        set ip 192.0.2.10 255.255.255.0
        set allowaccess ping https ssh
    next
end
config system admin
    edit "secops"
        set two-factor fortitoken
    next
end
"""


def test_representative_configuration_crosses_parser_registry_and_typed_engine() -> None:
    configuration = FortiGateParser().parse(SYNTHETIC_CONFIG)

    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.hostname == "vysion-lab.example"
    assert [finding.control_id for finding in findings] == [
        "SYS-HOSTNAME-001",
        "NET-WAN-MGMT-001",
        "IAM-ADMIN-MFA-001",
    ]
    assert [finding.status for finding in findings] == [
        AuditStatus.PASS,
        AuditStatus.FAIL,
        AuditStatus.PASS,
    ]
    assert findings[1].evidence == ("wan1: allowaccess includes ssh",)
    assert findings[1].recommendation is not None


def test_parser_rejects_non_fortigate_text() -> None:
    try:
        FortiGateParser().parse("this is not a FortiGate configuration")
    except ValueError as exc:
        assert str(exc) == "unsupported or incomplete FortiGate configuration"
    else:
        raise AssertionError("invalid input must be rejected")


def test_parser_rejects_truncated_configuration() -> None:
    raw = '''config system global
    set hostname "truncated.example"
'''

    try:
        FortiGateParser().parse(raw)
    except ValueError as exc:
        assert str(exc) == "unsupported or incomplete FortiGate configuration"
    else:
        raise AssertionError("truncated configuration must be rejected")


def test_parser_rejects_nested_unsupported_section_in_audited_entry() -> None:
    raw = '''config system interface
    edit "wan1"
        set allowaccess ping https
        config secondaryip
            edit 1
                set allowaccess ping ssh
            next
        end
    next
end
'''

    try:
        FortiGateParser().parse(raw)
    except ValueError as exc:
        assert str(exc) == "unsupported nested section in audited entry"
    else:
        raise AssertionError("nested unsupported section must fail closed")


def test_frozen_findings_do_not_expose_mutable_evidence() -> None:
    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(SYNTHETIC_CONFIG))

    assert isinstance(findings[0].evidence, tuple)


def test_missing_audited_sections_produce_unknown_instead_of_pass() -> None:
    raw = '''config system global
    set hostname "partial.example"
end
'''

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert [finding.status for finding in findings] == [
        AuditStatus.PASS,
        AuditStatus.UNKNOWN,
        AuditStatus.UNKNOWN,
    ]


def test_parser_rejects_uninterpreted_directive_in_audited_entry() -> None:
    raw = '''config system interface
    edit "wan1"
        append allowaccess ssh
    next
end
'''

    with pytest.raises(ValueError, match="unsupported directive in audited entry"):
        FortiGateParser().parse(raw)


def test_missing_global_section_produces_unknown_hostname() -> None:
    raw = '''config system interface
    edit "lan"
        set allowaccess ping
    next
end
config system admin
    edit "admin"
        set two-factor fortitoken
    next
end
'''

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[0].status is AuditStatus.UNKNOWN


def test_empty_audited_sections_produce_unknown() -> None:
    raw = '''config system global
    set hostname "partial.example"
end
config system interface
end
config system admin
end
'''

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert [finding.status for finding in findings] == [
        AuditStatus.PASS,
        AuditStatus.UNKNOWN,
        AuditStatus.UNKNOWN,
    ]


def test_unknown_mfa_method_produces_unknown_instead_of_pass() -> None:
    raw = '''config system admin
    edit "admin"
        set two-factor unsupported-method
    next
end
'''

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[2].status is AuditStatus.UNKNOWN


def test_parser_rejects_duplicate_directive_in_audited_entry() -> None:
    raw = '''config system interface
    edit "wan1"
        set allowaccess ssh
        set allowaccess ping
    next
end
'''

    with pytest.raises(ValueError, match="duplicate directive in audited entry"):
        FortiGateParser().parse(raw)


def test_parser_rejects_malformed_allowaccess_value() -> None:
    raw = '''config system interface
    edit "wan1"
        set allowaccess "ping ssh" garbage
    next
end
'''

    with pytest.raises(ValueError, match="invalid allowaccess value"):
        FortiGateParser().parse(raw)


def test_empty_global_section_is_unknown_but_nonempty_without_hostname_fails() -> None:
    empty = '''config system global
end
config system interface
    edit "lan"
        set allowaccess ping
    next
end
'''
    nonempty = '''config system global
    set admin-sport 8443
end
'''

    empty_findings = AuditEngine(default_registry()).run(FortiGateParser().parse(empty))
    nonempty_findings = AuditEngine(default_registry()).run(FortiGateParser().parse(nonempty))

    assert empty_findings[0].status is AuditStatus.UNKNOWN
    assert nonempty_findings[0].status is AuditStatus.FAIL


@pytest.mark.parametrize(
    ("section", "directive"),
    [
        ("system interface", "set allowacces ssh"),
        ("system admin", "set twofactor fortitoken"),
    ],
)
def test_parser_rejects_unsupported_set_key_in_audited_entry(
    section: str,
    directive: str,
) -> None:
    raw = f'''config {section}
    edit "item"
        {directive}
    next
end
'''

    with pytest.raises(ValueError, match="unsupported set key in audited entry"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize("hostname", ["   ", "fortigate ", " FORTIGATE"])
def test_blank_or_generic_hostname_never_passes(hostname: str) -> None:
    raw = f'''config system global
    set hostname "{hostname}"
end
'''

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[0].status is AuditStatus.FAIL


def test_parser_rejects_unbalanced_edit_quote() -> None:
    raw = '''config system interface
    edit "wan1
        set allowaccess ping
    next
end
'''

    with pytest.raises(ValueError, match="malformed edit directive"):
        FortiGateParser().parse(raw)


def test_parser_rejects_content_after_last_end() -> None:
    raw = '''config system global
    set hostname "valid.example"
end
arbitrary trailing garbage
'''

    with pytest.raises(ValueError, match="content outside configuration block"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "unsupported",
    [
        "unset hostname",
        "append hostname suffix",
        "config unsupported-child\n    end",
    ],
)
def test_parser_rejects_unsupported_mutation_in_global_section(
    unsupported: str,
) -> None:
    raw = f'''config system global
    set hostname "valid.example"
    {unsupported}
end
'''

    with pytest.raises(ValueError, match="unsupported content in audited section"):
        FortiGateParser().parse(raw)


def test_parser_rejects_duplicate_top_level_audited_section() -> None:
    raw = '''config system global
    set hostname fortigate
end
config system global
    set hostname valid.example
end
'''

    with pytest.raises(ValueError, match="duplicate audited section"):
        FortiGateParser().parse(raw)


def test_wan_interface_without_allowaccess_is_unknown() -> None:
    raw = '''config system interface
    edit "wan1"
        set ip 192.0.2.1 255.255.255.0
    next
end
'''

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[1].status is AuditStatus.UNKNOWN


def test_parser_rejects_edit_in_global_section() -> None:
    raw = '''config system global
    edit "unexpected"
        set hostname "valid.example"
    next
end
'''

    with pytest.raises(ValueError, match="unsupported content in audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "allowaccess",
    [
        "unknown-protocol",
        "ping ssh unknown-protocol",
    ],
)
def test_parser_rejects_unknown_allowaccess_token(allowaccess: str) -> None:
    raw = f'''config system interface
    edit "wan1"
        set allowaccess {allowaccess}
    next
end
'''

    with pytest.raises(ValueError, match="unsupported allowaccess value"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    ("section", "directive"),
    [
        ("system interface", "set allowaccess ssh"),
        ("system admin", "set two-factor fortitoken"),
    ],
)
def test_parser_rejects_set_outside_entry_in_audited_entry_section(
    section: str,
    directive: str,
) -> None:
    raw = f'''config {section}
    {directive}
end
'''

    with pytest.raises(ValueError, match="set outside entry in audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    ("section", "directive"),
    [
        ("system interface", "unset allowaccess"),
        ("system admin", "append two-factor fortitoken"),
    ],
)
def test_parser_rejects_mutation_outside_entry_in_audited_entry_section(
    section: str,
    directive: str,
) -> None:
    raw = f'''config {section}
    {directive}
end
'''

    with pytest.raises(ValueError, match="unsupported content in audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "audited_section",
    ["system global", "system interface", "system admin"],
)
def test_parser_rejects_audited_section_nested_under_unknown_wrapper(
    audited_section: str,
) -> None:
    raw = f'''config vendor
    config {audited_section}
    end
end
'''

    with pytest.raises(ValueError, match="audited section must be top-level"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "audited_section",
    ["system  global", "system  interface", "system  admin"],
)
def test_parser_normalizes_audited_section_whitespace_before_enforcing_top_level(
    audited_section: str,
) -> None:
    raw = f'''config vendor
    config {audited_section}
    end
end
'''

    with pytest.raises(ValueError, match="audited section must be top-level"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    ("section", "body", "finding_index", "expected"),
    [
        ("system global", "set hostname fortigate", 0, AuditStatus.FAIL),
        (
            "system interface",
            "edit wan1\n        set allowaccess ping ssh\n    next",
            1,
            AuditStatus.FAIL,
        ),
        (
            "system admin",
            "edit admin\n        set two-factor none\n    next",
            2,
            AuditStatus.FAIL,
        ),
    ],
)
def test_parser_does_not_hide_quoted_audited_section(
    section: str,
    body: str,
    finding_index: int,
    expected: AuditStatus,
) -> None:
    raw = f'''config "{section}"
    {body}
end
'''

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[finding_index].status is expected


@pytest.mark.parametrize(
    "audited_section",
    ["system global", "system interface", "system admin"],
)
def test_parser_detects_tab_separated_audited_section_under_wrapper(
    audited_section: str,
) -> None:
    raw = f'''config vendor
    config\t"{audited_section}"
    end
end
'''

    with pytest.raises(ValueError, match="audited section must be top-level"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "malformed_section",
    [
        "system global extra",
        "system interface extra",
        "system admin extra",
    ],
)
@pytest.mark.parametrize("wrapper", [False, True])
def test_parser_rejects_audited_section_with_trailing_tokens(
    malformed_section: str,
    wrapper: bool,
) -> None:
    prefix = "config wrapper\n" if wrapper else ""
    suffix = "\nend" if wrapper else ""
    raw = f"{prefix}config {malformed_section}\nend{suffix}\n"

    with pytest.raises(ValueError, match="malformed audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    ("raw", "expected_error"),
    [
        (
            'config wrapper\nconfig "system  global"\n set hostname fortigate\nend\nend\n',
            "audited section must be top-level",
        ),
        (
            'config wrapper\nconfig "system"global\nend\nend\n',
            "malformed config directive",
        ),
    ],
)
def test_parser_rejects_ambiguous_quoted_audited_section(
    raw: str,
    expected_error: str,
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "hostname",
    [
        "fortigate;",
        "fortigate#comment",
        '"fortigate"garbage',
        "fortigate/extra",
        "-edge01",
        "edge01-",
        "edge..01",
    ],
)
def test_parser_rejects_malformed_hostname(hostname: str) -> None:
    raw = f'''config system global
    set hostname {hostname}
end
'''

    with pytest.raises(ValueError, match="malformed set directive|invalid hostname value"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "hostname",
    ["edge01", "edge-01", "edge-01.example", "FGT100F-A1"],
)
def test_parser_accepts_valid_hostname_syntax(hostname: str) -> None:
    raw = f'''config system global
    set hostname {hostname}
end
'''

    configuration = FortiGateParser().parse(raw)

    assert configuration.hostname == hostname


@pytest.mark.parametrize(
    ("raw", "expected_error"),
    [
        (
            "config wrapper\nconfig 'system'interface\nend\nend\n",
            "malformed config directive",
        ),
        (
            "config system global\nset hostname 'fortigate'garbage\nend\n",
            "malformed set directive",
        ),
    ],
)
def test_parser_rejects_single_quote_token_concatenation(
    raw: str,
    expected_error: str,
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "malformed_section",
    [
        "system interface;",
        "system/interface",
        "system interface#comment",
        "system interface/extra",
        "system interface_legacy",
    ],
)
def test_parser_rejects_punctuation_in_section_name(malformed_section: str) -> None:
    raw = f'''config wrapper
    config {malformed_section}
    end
end
'''

    with pytest.raises(ValueError, match="invalid section name"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "malformed_directive",
    [
        "Config system interface",
        "CONFIG system interface",
        "config; system interface",
        "Edit wan1",
        "Set allowaccess ssh",
        "Next",
        "End",
    ],
)
def test_parser_rejects_malformed_reserved_directive(
    malformed_directive: str,
) -> None:
    raw = f'''config wrapper
    {malformed_directive}
end
'''

    with pytest.raises(ValueError, match="malformed reserved directive"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "nested_section",
    [
        "system interface",
        "system interface-extra",
        "unrelated child",
    ],
)
def test_parser_rejects_every_nested_section(nested_section: str) -> None:
    raw = f'''config unrelated-wrapper
    config {nested_section}
    end
end
'''

    with pytest.raises(
        ValueError,
        match="nested section|must be top-level|malformed audited section",
    ):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "section",
    [
        "system global-extra",
        "system globalextra",
        "system interface-extra",
        "system interfaceextra",
        "system admin-extra",
        "system adminextra",
    ],
)
def test_parser_rejects_attached_audited_section_suffix(section: str) -> None:
    raw = f'''config {section}
end
'''

    with pytest.raises(ValueError, match="malformed audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "config system global\nset hostname fortigate\\q\nend\n",
        "config system admin\nedit admin\nset two-factor f\\ortitoken\nnext\nend\n",
        "config system global\nset hostname \"\\u00a0valid.example\\u00a0\"\nend\n",
        "config system global\nset hostname valid.example\\x00\nend\n",
    ],
)
def test_parser_rejects_lexical_transformations(raw: str) -> None:
    with pytest.raises(ValueError, match="invalid character|malformed .* directive"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "section",
    [
        "systemglobal",
        "systemglobals",
        "system global-extra",
        "system globalextra",
        "systeminterface",
        "system interfaces",
        "system interface-extra",
        "system interfaceextra",
        "systemadmin",
        "system admins",
        "system admin-extra",
        "system adminextra",
    ],
)
def test_parser_rejects_all_audited_section_lookalikes(section: str) -> None:
    with pytest.raises(ValueError, match="malformed audited section"):
        FortiGateParser().parse(f"config {section}\nend\n")


@pytest.mark.parametrize(
    "hostname",
    ['" valid.example"', '"valid.example "', '" valid.example "'],
)
def test_parser_rejects_valid_hostname_with_padding(hostname: str) -> None:
    raw = f"config system global\nset hostname {hostname}\nend\n"

    with pytest.raises(ValueError, match="invalid hostname value"):
        FortiGateParser().parse(raw)


def test_parser_rejects_unquoted_trailing_whitespace() -> None:
    raw = "config system global\nset hostname fortigate \nend\n"

    with pytest.raises(ValueError, match="trailing whitespace"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize("section", ["system interface", "system admin"])
def test_parser_rejects_nested_section_in_audited_section(section: str) -> None:
    raw = f'''config {section}
    config hidden
    end
end
'''

    with pytest.raises(ValueError, match="unsupported nested section in audited section"):
        FortiGateParser().parse(raw)
