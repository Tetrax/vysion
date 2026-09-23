"""Wall clock shared by the application and the root certificate helper.

Kept free of any project dependency on purpose: ``vysion.certhelper`` imports
the certificate engine under the host's plain ``python3``, where the report
stack — and therefore pydantic — is not installed.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)
