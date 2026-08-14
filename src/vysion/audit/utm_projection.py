from __future__ import annotations

from dataclasses import dataclass

from vysion.audit.models import (
    EvidenceCertainty,
    FortiGateConfiguration,
    ProofState,
    StructuralDirective,
    StructuralEntry,
    StructuralSection,
    UtmCategoryRule,
    UtmProfile,
)


@dataclass(frozen=True)
class UtmProjection:
    profiles: tuple[UtmProfile, ...] = ()


def _directives(
    directives: tuple[StructuralDirective, ...],
    invalidated_keys: frozenset[str],
) -> tuple[dict[str, StructuralDirective], frozenset[str]]:
    result: dict[str, StructuralDirective] = {}
    invalidated = set(invalidated_keys)
    for directive in directives:
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
    directives: dict[str, StructuralDirective],
    key: str,
    invalidated: set[str],
) -> str | None:
    directive = directives.get(key)
    if directive is None:
        return None
    if len(directive.tokens) != 1:
        invalidated.add(key)
        return None
    return directive.tokens[0].casefold()


def _child(entry: StructuralEntry, name: str) -> StructuralSection | None:
    matches = tuple(child for child in entry.children if child.name.casefold() == name.casefold())
    return matches[0] if len(matches) == 1 else None


def _category_rule(entry: StructuralEntry) -> UtmCategoryRule:
    directives, initial_invalidated = _directives(entry.directives, entry.invalidated_keys)
    invalidated = set(initial_invalidated)
    category_tokens = directives.get("category")
    categories: list[int] = []
    if category_tokens is not None:
        for token in category_tokens.tokens:
            try:
                categories.append(int(token, 10))
            except ValueError:
                invalidated.add("category")
                categories.clear()
                break
    action = _single(directives, "action", invalidated)
    final_invalidated = frozenset(invalidated)
    parsed = frozenset(set(directives) - set(final_invalidated))
    return UtmCategoryRule(
        name=entry.name,
        categories=tuple(categories),
        action=action,
        parsed_keys=parsed,
        invalidated_keys=final_invalidated,
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN
            and "category" in parsed
            and not final_invalidated
            else ProofState.UNKNOWN
        ),
    )


def _webfilter_profile(entry: StructuralEntry) -> UtmProfile:
    invalidated: set[str] = set(entry.invalidated_keys)
    parsed: set[str] = set()
    blocklist_enabled: bool | None = None
    error_allow: bool | None = None
    category_rules: tuple[UtmCategoryRule, ...] = ()

    web = _child(entry, "web")
    if web is None or web.certainty is not EvidenceCertainty.CERTAIN:
        invalidated.add("blocklist")
    else:
        directives, child_invalidated = _directives(web.directives, web.invalidated_keys)
        invalidated.update(child_invalidated)
        value = _single(directives, "blocklist", invalidated)
        if value in {"enable", "disable"}:
            blocklist_enabled = value == "enable"
            parsed.add("blocklist")
        elif value is not None:
            invalidated.add("blocklist")

    ftgd = _child(entry, "ftgd-wf")
    if ftgd is None or ftgd.certainty is not EvidenceCertainty.CERTAIN:
        invalidated.update({"options", "filters"})
    else:
        directives, child_invalidated = _directives(ftgd.directives, ftgd.invalidated_keys)
        invalidated.update(child_invalidated)
        options = directives.get("options")
        if options is not None and options.tokens:
            error_allow = "error-allow" in {token.casefold() for token in options.tokens}
            parsed.add("options")
        filters = tuple(child for child in ftgd.children if child.name.casefold() == "filters")
        if len(filters) != 1 or filters[0].certainty is not EvidenceCertainty.CERTAIN:
            invalidated.add("filters")
        else:
            category_rules = tuple(_category_rule(item) for item in filters[0].entries)
            if filters[0].entries and all(
                rule.proof_state is ProofState.PROVEN for rule in category_rules
            ):
                parsed.add("filters")
            else:
                invalidated.add("filters")

    final_invalidated = frozenset(invalidated)
    return UtmProfile(
        name=entry.name,
        profile_type="webfilter profile",
        blocklist_enabled=blocklist_enabled,
        error_allow=error_allow,
        category_rules=category_rules,
        parsed_keys=frozenset(parsed),
        invalidated_keys=final_invalidated,
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN
            and {"blocklist", "options", "filters"} <= parsed
            and not final_invalidated
            else ProofState.UNKNOWN
        ),
    )


def _dnsfilter_profile(entry: StructuralEntry) -> UtmProfile:
    directives, initial_invalidated = _directives(entry.directives, entry.invalidated_keys)
    invalidated = set(initial_invalidated)
    parsed: set[str] = set()
    blocklists: tuple[str, ...] = ()
    blocklist = directives.get("external-ip-blocklist")
    if blocklist is not None and blocklist.tokens:
        blocklists = blocklist.tokens
        parsed.add("external-ip-blocklist")
    else:
        invalidated.add("external-ip-blocklist")

    error_allow: bool | None = None
    category_rules: tuple[UtmCategoryRule, ...] = ()
    ftgd = _child(entry, "ftgd-dns")
    if ftgd is None or ftgd.certainty is not EvidenceCertainty.CERTAIN:
        invalidated.update({"options", "filters"})
    else:
        ftgd_directives, child_invalidated = _directives(
            ftgd.directives, ftgd.invalidated_keys
        )
        invalidated.update(child_invalidated)
        options = ftgd_directives.get("options")
        if options is not None and options.tokens:
            error_allow = "error-allow" in {token.casefold() for token in options.tokens}
            parsed.add("options")
        else:
            invalidated.add("options")
        filters = tuple(child for child in ftgd.children if child.name.casefold() == "filters")
        if len(filters) != 1 or filters[0].certainty is not EvidenceCertainty.CERTAIN:
            invalidated.add("filters")
        else:
            category_rules = tuple(_category_rule(item) for item in filters[0].entries)
            if filters[0].entries and all(
                rule.proof_state is ProofState.PROVEN for rule in category_rules
            ):
                parsed.add("filters")
            else:
                invalidated.add("filters")

    final_invalidated = frozenset(invalidated)
    return UtmProfile(
        name=entry.name,
        profile_type="dnsfilter profile",
        error_allow=error_allow,
        external_ip_blocklists=blocklists,
        category_rules=category_rules,
        parsed_keys=frozenset(parsed),
        invalidated_keys=final_invalidated,
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN
            and {"external-ip-blocklist", "options", "filters"} <= parsed
            and not final_invalidated
            else ProofState.UNKNOWN
        ),
    )


def _root_profile(
    entry: StructuralEntry,
    profile_type: str,
    keys: tuple[str, ...],
    *,
    category_child: str | None = None,
    required_keys: tuple[str, ...] | None = None,
    multi_keys: tuple[str, ...] = (),
) -> UtmProfile:
    directives, initial_invalidated = _directives(entry.directives, entry.invalidated_keys)
    invalidated = set(initial_invalidated)
    parsed: set[str] = set()
    values: dict[str, str | None] = {}
    tokens: dict[str, tuple[str, ...]] = {}
    for key in keys:
        directive = directives.get(key)
        if directive is None:
            continue
        tokens[key] = directive.tokens
        if key in multi_keys:
            if directive.tokens:
                parsed.add(key)
            else:
                invalidated.add(key)
            continue
        value = _single(directives, key, invalidated)
        if value is not None:
            values[key] = value
            parsed.add(key)

    category_rules: tuple[UtmCategoryRule, ...] = ()
    if category_child is not None:
        child = _child(entry, category_child)
        if child is None or child.certainty is not EvidenceCertainty.CERTAIN:
            invalidated.add(category_child)
        else:
            category_rules = tuple(_category_rule(item) for item in child.entries)
            if child.entries and all(
                rule.proof_state is ProofState.PROVEN for rule in category_rules
            ):
                parsed.add(category_child)
            else:
                invalidated.add(category_child)

    final_invalidated = frozenset(invalidated)
    return UtmProfile(
        name=entry.name,
        profile_type=profile_type,
        external_blocklist_all=(
            values.get("external-blocklist-enable-all") == "enable"
            if "external-blocklist-enable-all" in parsed
            else None
        ),
        external_blocklists=tokens.get("external-blocklist", ()),
        analytics_db_enabled=(
            values.get("analytics-db") == "enable" if "analytics-db" in parsed else None
        ),
        block_malicious_url_enabled=(
            values.get("block-malicious-url") == "enable"
            if "block-malicious-url" in parsed
            else None
        ),
        scan_botnet_connections=values.get("scan-botnet-connections"),
        category_rules=category_rules,
        parsed_keys=frozenset(parsed),
        invalidated_keys=final_invalidated,
        proof_state=(
            ProofState.PROVEN
            if entry.certainty is EvidenceCertainty.CERTAIN
            and set(required_keys if required_keys is not None else keys) <= parsed
            and (category_child is None or category_child in parsed)
            and not final_invalidated
            else ProofState.UNKNOWN
        ),
    )


def project_utm(document) -> UtmProjection:
    profiles: list[UtmProfile] = []
    for section in document.sections:
        if section.name == "webfilter profile":
            profiles.extend(_webfilter_profile(entry) for entry in section.entries)
        elif section.name == "dnsfilter profile":
            profiles.extend(_dnsfilter_profile(entry) for entry in section.entries)
        elif section.name == "antivirus profile":
            profiles.extend(
                _root_profile(
                    entry,
                    "antivirus profile",
                    (
                        "analytics-db",
                        "external-blocklist-enable-all",
                        "external-blocklist",
                    ),
                    required_keys=("analytics-db",),
                    multi_keys=("external-blocklist",),
                )
                for entry in section.entries
            )
        elif section.name == "ips sensor":
            profiles.extend(
                _root_profile(
                    entry,
                    "ips sensor",
                    ("block-malicious-url", "scan-botnet-connections"),
                )
                for entry in section.entries
            )
        elif section.name == "application list":
            profiles.extend(
                _root_profile(entry, "application list", (), category_child="entries")
                for entry in section.entries
            )
    return UtmProjection(profiles=tuple(profiles))


def apply_utm_projection(
    configuration: FortiGateConfiguration,
    projection: UtmProjection,
) -> FortiGateConfiguration:
    return configuration.model_copy(update={"utm_profiles": projection.profiles})
