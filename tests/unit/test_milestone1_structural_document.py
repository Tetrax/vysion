from vysion.audit.models import EvidenceCertainty, FortiGateConfiguration, StructuralDocument
from vysion.audit.parser import FortiGateParser


def test_parser_preserves_structural_sections_directives_tokens_and_lines() -> None:
    raw = """config system interface
    edit "wan1"
        set allowaccess ping https
    next
end
"""

    configuration: FortiGateConfiguration = FortiGateParser().parse(raw)
    document: StructuralDocument = configuration.document
    section = document.section("system interface")

    assert document.valid is True
    assert document.certainty is EvidenceCertainty.CERTAIN
    assert section is not None
    assert section.line == 1
    assert section.entries[0].name == "wan1"
    directive = section.entries[0].directives[0]
    assert directive.name == "allowaccess"
    assert directive.tokens == ("ping", "https")
    assert directive.line == 3
    assert directive.certainty is EvidenceCertainty.CERTAIN


def test_parser_invalidates_structured_evidence_for_ambiguous_mutation() -> None:
    raw = """config system interface
    edit "wan1"
        set allowaccess ping
        append allowaccess ssh
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    section = configuration.document.section("system interface")

    assert section is not None
    entry = section.entries[0]
    assert entry.certainty is EvidenceCertainty.AMBIGUOUS
    assert entry.parsed_keys == frozenset()
    assert "allowaccess" in entry.invalidated_keys
    assert configuration.interfaces[0].proof_state.value == "unknown"
