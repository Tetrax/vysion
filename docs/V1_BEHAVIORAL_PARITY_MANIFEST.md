# V1/V2 Behavioral Parity Work Manifest

Baseline captured: `2026-08-19T15:44:46Z`

## Scope

Reach behavioral parity with the V1 business oracle while preserving the V2 production architecture: structural parser, typed projections, `AuditContext`, `AuditFinding`, registry, canonical JSON, and V2 renderers.

The legacy implementation is an isolated comparison oracle only. It is never copied into the V2 runtime or image.

## Protected baseline

- Base branch/commit: `main@23e219b11a18bcc6d5ff90799f3cdd6739883953`
- Work branch: `feat/v1-behavioral-parity`
- Production version/image: `2.3.5` / `vysion:23e219b11a18bcc6d5ff90799f3cdd6739883953`
- Runtime at baseline: `vysion-vysion-1`, healthy, restart count 0
- Rollback images retained: `vysion:rollback-v2.3.3`, `vysion:rollback-v2.3.4`
- V1 oracle (read-only, outside this repository): `/home/tetrax/workspace/vysion/audit-fgt-vysion/backend/app/audit/legacy_functions.py`
- Real reference configuration: temporary input outside Git; its contents and generated reports must not be persisted.

## Baseline gates

- Backend: `788 passed`
- Ruff: all checks passed
- Frontend: 3 files / 10 tests passed
- Frontend lint: passed
- Frontend build: passed
- Compose validation: passed
- External `/healthz` and `/api/health`: version `2.3.5`, expected revision

## Differential contract

Compare status/applicability, business rule and thresholds, evidence and affected objects, operator context, interface/zone/SD-WAN selection, missing/incomplete/mutated/ambiguous/non-applicable configuration behavior, and external/runtime dependencies.

Every correction requires a red-capable differential regression test first. Missing proof remains `UNKNOWN`; conditional irrelevance remains distinct from proven `NOT_APPLICABLE`.

## Deliverables

1. Exhaustive V1 capability to V2 finding/projection mapping.
2. Deterministic isolated V1 replay under Python 3.12.
3. Synthetic differential corpus plus temporary real-reference replay.
4. Canonical, client-data-free parity matrix and report.
5. Focused parser/projection and business-semantic corrections.
6. Explicit contracts or documented `UNKNOWN` limits for EOL and runtime hit counts.
7. Full backend/frontend/lint/build regression evidence.
8. Clean release-candidate branch; no production deployment.
