"""Settings: ``none | local | helper``, hostname mandatory when managed.

``local`` keeps deriving the authoritative origin from the name it serves;
``helper`` runs on a VPS behind a host proxy, so the origin stays an explicit
operator value and is never borrowed from a Host header.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vysion.config import Settings


def _settings(tmp_path: Path, **overrides) -> Settings:
    values = {
        "report_directory": tmp_path / "reports",
        "state_directory": tmp_path / "state",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize("backend", ["none", "local", "helper"])
def test_the_three_backends_are_accepted(tmp_path: Path, backend: str) -> None:
    settings = _settings(
        tmp_path, tls_backend=backend, tls_hostname="vysion.example"
    )
    assert settings.tls_backend == backend


def test_an_unknown_backend_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _settings(tmp_path, tls_backend="apache")


@pytest.mark.parametrize("backend", ["local", "helper"])
def test_a_managed_backend_requires_a_valid_hostname(
    tmp_path: Path, backend: str
) -> None:
    with pytest.raises(ValueError):
        _settings(tmp_path, tls_backend=backend, tls_hostname="")
    with pytest.raises(ValueError):
        _settings(tmp_path, tls_backend=backend, tls_hostname="not a host!")


def test_helper_does_not_derive_the_public_origin(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path, tls_backend="helper", tls_hostname="vysion.example"
    )
    # The host proxy owns the public name: an operator states it explicitly
    # rather than letting a derived value become the Origin authority.
    assert settings.public_origin == ""


def test_local_still_derives_the_public_origin(tmp_path: Path) -> None:
    settings = _settings(tmp_path, tls_backend="local", tls_hostname="vysion.example")
    assert settings.public_origin == "https://vysion.example"


def test_the_helper_socket_path_is_configurable(tmp_path: Path) -> None:
    custom = tmp_path / "run" / "helper.sock"
    settings = _settings(
        tmp_path,
        tls_backend="helper",
        tls_hostname="vysion.example",
        helper_socket_path=custom,
    )
    assert settings.helper_socket_path == custom
    default = _settings(tmp_path, tls_backend="helper", tls_hostname="vysion.example")
    assert str(default.helper_socket_path) == "/run/vysion-cert-helper/helper.sock"


def test_none_keeps_no_hostname_requirement(tmp_path: Path) -> None:
    settings = _settings(tmp_path, tls_backend="none")
    assert settings.tls_hostname == ""
    assert settings.public_origin == ""
