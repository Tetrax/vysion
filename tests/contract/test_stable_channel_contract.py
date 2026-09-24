"""Contract of the one-click update channel for the online Portainer
standalone install (decision 0011).

Four things must hold together for « Portainer → Stacks → Vysion →
Update the stack » to deliver a new build with no variable to edit:

* ``compose.standalone.yml`` tracks ``ghcr.io/tetrax/vysion:stable`` and
  forces a pull, so the deployment re-acquires the manifest;
* every other stack keeps the immutable digest contract;
* CI promotes ``stable`` only after the three gates, only on a push to
  ``main`` — never from a pull request;
* the human tag ``sha-<commit>`` and the OCI revision label survive, so
  what actually runs stays verifiable and rollback stays possible.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-container.yml"
STANDALONE = ROOT / "compose.standalone.yml"
STABLE_IMAGE = "ghcr.io/tetrax/vysion:stable"
DIGEST_PINNED_STACKS = ("compose.yml", "compose.proxy.yml", "compose.helper.yml")
STABLE_VOLUMES = {"vysion-reports", "vysion-state", "vysion-certs"}


def _service(path: Path) -> dict:
    return yaml.safe_load(path.read_text())["services"]["vysion"]


def _require_docker_compose() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is required to render compose.standalone.yml")
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("the docker compose plugin is required to render compose.standalone.yml")


def _clean_env(**env: str) -> dict[str, str]:
    """No IMAGE_* value ever leaks from the caller's environment."""
    clean = {key: value for key, value in os.environ.items() if not key.startswith("IMAGE_")}
    clean.update(env)
    return clean


def _render_standalone(empty_env: Path, **env: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "compose.standalone.yml",
            "--env-file",
            str(empty_env),
            "config",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=_clean_env(**env),
        check=False,
    )


def test_only_the_online_standalone_stack_tracks_the_stable_channel() -> None:
    """Scope of the channel: one stack consumes `stable`, every other stack
    keeps its own immutable contract — proxy/VPS/helper by digest, offline
    by the imported tag — and none of them grew a pull policy."""
    raw = STANDALONE.read_text()
    service = _service(STANDALONE)
    assert service["image"] == STABLE_IMAGE
    # The re-pull is what makes "Update the stack" do anything at all.
    assert service["pull_policy"] == "always"
    assert "${" not in service["image"]
    assert "${IMAGE_DIGEST" not in raw

    for name in DIGEST_PINNED_STACKS:
        text = (ROOT / name).read_text()
        pinned = _service(ROOT / name)
        assert STABLE_IMAGE not in text, name
        assert pinned["image"].startswith("ghcr.io/tetrax/vysion@${IMAGE_DIGEST"), name
        assert ":?" in pinned["image"], name
        assert "pull_policy" not in pinned, name

    offline_raw = (ROOT / "compose.standalone.offline.yml").read_text()
    offline = _service(ROOT / "compose.standalone.offline.yml")
    assert STABLE_IMAGE not in offline_raw
    assert offline["image"].startswith("${VYSION_IMAGE:?")
    assert "pull_policy" not in offline


def test_the_online_standalone_stack_renders_with_the_hostname_alone(
    tmp_path: Path,
) -> None:
    """No IMAGE_DIGEST is entered on a fresh online install: the stack
    resolves from VYSION_TLS_HOSTNAME alone, keeps the three stable volume
    names (data untouched), and an IMAGE_DIGEST in the environment is read
    by nothing."""
    _require_docker_compose()
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")

    missing = _render_standalone(empty_env)
    assert missing.returncode != 0, missing.stdout + missing.stderr
    assert "VYSION_TLS_HOSTNAME" in missing.stderr

    rendered = _render_standalone(empty_env, VYSION_TLS_HOSTNAME="vysion.example.com")
    assert rendered.returncode == 0, rendered.stdout + rendered.stderr
    compose = yaml.safe_load(rendered.stdout)
    service = compose["services"]["vysion"]
    assert service["image"] == STABLE_IMAGE
    assert service["pull_policy"] == "always"
    assert "IMAGE_DIGEST" not in rendered.stdout
    assert set(compose["volumes"]) == STABLE_VOLUMES
    for volume in STABLE_VOLUMES:
        # Compose-managed, never external: a Portainer-only install creates them.
        assert "external" not in compose["volumes"][volume]

    ignored = _render_standalone(
        empty_env,
        VYSION_TLS_HOSTNAME="vysion.example.com",
        IMAGE_DIGEST="sha256:" + "ab" * 32,
    )
    assert ignored.returncode == 0, ignored.stdout + ignored.stderr
    assert yaml.safe_load(ignored.stdout)["services"]["vysion"]["image"] == STABLE_IMAGE


def test_ci_promotes_stable_only_after_the_gates_on_main() -> None:
    """The single mutable tag moves in exactly one place: the publish job,
    which needs all three gates, under an event/ref condition that a pull
    request can never satisfy."""
    raw = WORKFLOW.read_text()
    workflow = yaml.safe_load(raw)
    jobs = workflow["jobs"]
    publish = jobs["publish"]

    assert set(publish["needs"]) == {"python", "frontend", "stack"}
    assert publish["if"] == "github.event_name != 'pull_request'"

    promote = next(
        step for step in publish["steps"] if "stable channel" in str(step.get("name", ""))
    )
    assert promote["if"] == "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    run = promote["run"]
    assert f"docker buildx imagetools create --tag {STABLE_IMAGE}" in run
    assert "imagetools inspect" in run
    assert "exit 1" in run

    build = next(
        step
        for step in publish["steps"]
        if str(step.get("uses", "")).startswith("docker/build-push-action")
    )
    assert build["with"]["tags"] == "ghcr.io/tetrax/vysion:sha-${{ github.sha }}"
    assert "org.opencontainers.image.revision=${{ github.sha }}" in build["with"]["labels"]

    # Exactly two image-publishing steps exist in the whole workflow: the
    # commit tag (ungated but never `stable`) and the gated promotion.
    pushing = []
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            uses = str(step.get("uses", ""))
            if uses.startswith("docker/build-push-action") or "imagetools create" in str(
                step.get("run", "")
            ):
                pushing.append((job_name, step))
    assert len(pushing) == 2, pushing
    for job_name, step in pushing:
        assert job_name == "publish", job_name
        if "imagetools create" in str(step.get("run", "")):
            assert step["if"] == promote["if"]
        else:
            assert step["with"]["tags"] == "ghcr.io/tetrax/vysion:sha-${{ github.sha }}"

    # PRs still run CI (they must), they just never publish: `stable` is
    # never built or pushed anywhere else, and no ambiguous `:latest` tag.
    assert "\n  pull_request:\n" in raw
    assert ":latest" not in raw


def test_the_runbook_and_the_readme_document_the_one_click_update() -> None:
    """Operator documentation: the exact click path, the verification it
    ends with, the real Portainer limitation and the rollback that does not
    hide the mutability trade-off."""
    operations = (ROOT / "docs/OPERATIONS.md").read_text().casefold()
    for marker in (
        "portainer → stacks → vysion → update the stack",
        "aucune variable à changer",
        "ghcr.io/tetrax/vysion:stable",
        "pull_policy: always",
        "healthy",
        "/healthz",
        "canal `stable`",
        "jamais depuis une pull request",
        "limite portainer réelle",
        "sha-<commit>",
        "rollback",
    ):
        assert marker in operations, marker

    readme = (ROOT / "README.md").read_text().casefold()
    for marker in (
        "ghcr.io/tetrax/vysion:stable",
        "pull_policy: always",
        "update the stack",
        "aucune variable à changer",
        "healthy",
        "/healthz",
        "rollback",
    ):
        assert marker in readme, marker

    security = (ROOT / "docs/SECURITY.md").read_text().casefold()
    for marker in (
        "ghcr.io/tetrax/vysion:stable",
        "pull_policy: always",
        "jamais depuis une pull request",
    ):
        assert marker in security, marker


def test_the_decision_record_states_the_mutable_channel_tradeoff() -> None:
    records = sorted((ROOT / "docs" / "decisions").glob("0011-*.json"))
    assert len(records) == 1, records
    record = json.loads(records[0].read_text())
    assert record["status"] == "accepted"

    decision = record["decision"].casefold()
    for marker in ("stable", "pull_policy: always", "jamais depuis une pull request"):
        assert marker in decision, marker

    rollback = record["rollback_boundary"].casefold()
    assert "sha-<commit>" in rollback
    assert "stable" in rollback
