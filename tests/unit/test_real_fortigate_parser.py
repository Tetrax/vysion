from pathlib import Path

import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "anonymized_fortigate_export.conf"


def test_anonymized_realistic_fortigate_export_is_audited() -> None:
    configuration = FortiGateParser().parse(_FIXTURE.read_text(encoding="utf-8"))

    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.hostname == "edge-lab.example"
    assert [interface.name for interface in configuration.interfaces] == ["wan1", "port1"]
    assert configuration.administrators[0].two_factor == "fortitoken"
    assert [finding.status for finding in findings] == [
        AuditStatus.PASS,
        AuditStatus.PASS,
        AuditStatus.PASS,
    ]


def test_utf8_bom_is_accepted() -> None:
    raw = "\ufeffconfig system global\n    set hostname edge-lab.example\nend\n"

    configuration = FortiGateParser().parse(raw)

    assert configuration.hostname == "edge-lab.example"


def test_unicode_in_comments_and_unused_values_is_accepted() -> None:
    raw = """# Export synthétique — équipe sécurité
config system interface
    edit "wan1"
        set allowaccess ping
        set description "Accès opérateur — générique"
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.interfaces[0].allowaccess == frozenset({"ping"})


def test_extra_keys_in_audited_entries_are_ignored() -> None:
    raw = """config system admin
    edit "secops"
        set accprofile "super_admin"
        set vdom "root"
        set two-factor fortitoken
        set email-to "secops@example.invalid"
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.administrators[0].two_factor == "fortitoken"


@pytest.mark.parametrize(
    "dangerous",
    [
        "\x00",
        "\x01",
        "\x1f",
        "\x7f",
        "\x85",
        "\u200b",
        "\u2028",
        "\u2029",
        "\u202e",
        "\ufeff",
    ],
)
def test_dangerous_control_characters_are_rejected(dangerous: str) -> None:
    raw = f"# invalid{dangerous}separator\nconfig system global\nend\n"

    with pytest.raises(ValueError, match="invalid .*character|invalid line separator"):
        FortiGateParser().parse(raw)


def test_no_identifiable_wan_interface_is_unknown() -> None:
    raw = """config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[1].status is AuditStatus.UNKNOWN


def test_missing_admin_mfa_directive_is_unknown() -> None:
    raw = """config system admin
    edit "secops"
        set accprofile "super_admin"
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[2].status is AuditStatus.UNKNOWN


def test_nested_subsection_does_not_become_parent_evidence() -> None:
    raw = """config system interface
    edit "wan1"
        config secondaryip
            edit 1
                set allowaccess ping ssh
            next
        end
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[1].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    ("section", "entry", "known_value", "mutation", "finding_index"),
    [
        ("system global", "", "set hostname edge-lab.example", "unset hostname", 0),
        (
            "system interface",
            'edit "wan1"',
            "set allowaccess ping",
            "append allowaccess ssh",
            1,
        ),
        (
            "system admin",
            'edit "secops"',
            "set two-factor fortitoken",
            "unset two-factor",
            2,
        ),
    ],
)
def test_uninterpreted_audited_mutation_is_unknown(
    section: str,
    entry: str,
    known_value: str,
    mutation: str,
    finding_index: int,
) -> None:
    suffix = "\n    next" if entry else ""
    raw = f"config {section}\n    {entry}\n        {known_value}\n        {mutation}{suffix}\nend\n"

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[finding_index].status is AuditStatus.UNKNOWN


def test_interface_role_wan_is_used_as_identification_evidence() -> None:
    raw = """config system interface
    edit "port1"
        set role wan
        set allowaccess ping https
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[1].status is AuditStatus.PASS


@pytest.mark.parametrize(
    "raw",
    [
        "config system global\n    set hostname edge\\q\nend\n",
        'config system global\n    set hostname "edge"lab.example\nend\n',
        'config system interface\n    edit "wan"1\n    next\nend\n',
    ],
)
def test_ambiguous_lexical_transformations_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match="malformed .* directive|invalid hostname value"):
        FortiGateParser().parse(raw)


def test_duplicate_top_level_audited_section_is_rejected() -> None:
    raw = """config system global
    set hostname first.example
end
config system global
    set hostname second.example
end
"""

    with pytest.raises(ValueError, match="duplicate audited section"):
        FortiGateParser().parse(raw)


def test_edit_in_system_global_is_rejected() -> None:
    raw = """config system global
    edit "unexpected"
        set hostname fabricated.example
    next
end
"""

    with pytest.raises(ValueError, match="unsupported edit in audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize("hostname", ['""', '"   "', '" fortigate "', '" FORTIGATE "'])
def test_explicit_blank_or_generic_hostname_is_fail(hostname: str) -> None:
    raw = f"config system global\n    set hostname {hostname}\nend\n"

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[0].status is AuditStatus.FAIL


def test_explicit_admin_mfa_failure_takes_precedence_over_unknown() -> None:
    raw = """config system admin
    edit "known-failure"
        set two-factor none
    next
    edit "unknown-state"
        set accprofile super_admin
    next
end
"""

    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))

    assert findings[2].status is AuditStatus.FAIL
    assert findings[2].evidence == ("administrateur sans MFA: known-failure",)


def test_non_audited_entry_names_are_not_lexically_interpreted() -> None:
    raw = """config firewall address
    edit "unused'O\\bject"
        set comment "Valeur Unicode — ignorée"
    next
end
config system global
    set hostname edge-lab.example
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.hostname == "edge-lab.example"


@pytest.mark.parametrize(
    "hidden_section",
    [
        "config system interface extra\n",
        "config system interface;\n",
        "config system interface-extra\n",
        "config system interface.extra\n",
        "config system interface/extra\n",
        "config system interface_extra\n",
        "config system interfaces\n",
        "config systeminterface\n",
        "config ignored wrapper\n    config system interface\n",
    ],
)
def test_ambiguous_or_nested_audited_sections_are_rejected(hidden_section: str) -> None:
    hidden_end = "    end\nend\n" if hidden_section.startswith("config ignored") else "end\n"
    raw = (
        hidden_section
        + '    edit "wan-hidden"\n'
        + "        set allowaccess ssh\n"
        + "    next\n"
        + hidden_end
        + "config system interface\n"
        + '    edit "wan1"\n'
        + "        set allowaccess ping https\n"
        + "    next\n"
        + "end\n"
    )

    with pytest.raises(ValueError, match="ambiguous or nested audited section"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize(
    "directive",
    [
        "set allowaccess ssh",
        "append allowaccess ssh",
        "unset allowaccess",
        'append "allowaccess" ssh',
    ],
)
def test_directives_outside_audited_entries_are_rejected(directive: str) -> None:
    raw = f"""config system interface
    {directive}
    edit "wan1"
        set allowaccess ping https
    next
end
"""

    with pytest.raises(ValueError, match="directive outside audited entry"):
        FortiGateParser().parse(raw)


@pytest.mark.parametrize("invalidating_directive", ["set hostname", 'unset "hostname"'])
def test_later_invalid_hostname_directive_removes_stale_pass(
    invalidating_directive: str,
) -> None:
    raw = f"""config system global
    set hostname safe.example
    {invalidating_directive}
end
"""

    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration)

    assert configuration.hostname is None
    assert findings[0].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    ("raw", "finding_index"),
    [
        (
            """config system interface
    edit "wan-hidden"
        SET allowaccess ssh
    next
    edit "wan1"
        set allowaccess ping https
    next
end
""",
            1,
        ),
        (
            """config system global
    set hostname safe.example
    set "hostname" fortigate
end
""",
            0,
        ),
    ],
)
def test_keyword_case_or_quoted_audited_key_never_preserves_pass(
    raw: str,
    finding_index: int,
) -> None:
    try:
        findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    except ValueError:
        return

    assert findings[finding_index].status is not AuditStatus.PASS


@pytest.mark.parametrize(
    "section",
    [
        "system-interface",
        "system.interface",
        "system/interface",
        "system_interface",
    ],
)
def test_separator_lookalikes_of_audited_sections_are_rejected(section: str) -> None:
    raw = f"""config {section}
    edit "wan-hidden"
        set allowaccess ssh
    next
end
config system interface
    edit "wan1"
        set allowaccess ping https
    next
end
"""

    with pytest.raises(ValueError, match="ambiguous or nested audited section"):
        FortiGateParser().parse(raw)


def test_reserved_directive_lookalike_after_proof_is_rejected() -> None:
    raw = """config system global
    set hostname safe.example
    setx hostname fortigate
end
"""

    with pytest.raises(ValueError, match="ambiguous directive"):
        FortiGateParser().parse(raw)
