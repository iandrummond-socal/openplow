"""Test-harness setup shared by every test module.

The ``unshare`` sandbox runs payloads in a minimal read-only root that holds only the
system runtimes under ``/usr`` (plus scratch, the target and any ``expose``d path).
Many tests run their payload with the absolute ``sys.executable`` of the interpreter
running pytest, and on a machine whose Python lives outside ``/usr`` (a venv in
``$HOME``, ``/opt/hostedtoolcache`` on GitHub runners) that interpreter would not be
visible inside the sandbox.

So, on Linux and only for tests, ``UnshareSandbox`` defaults ``expose`` to the roots
of the test interpreter when the caller does not pass ``expose`` at all. This is a
**test-harness convenience**: the product default stays empty, because exposing the
interpreter's prefix automatically would put a ``$HOME`` venv back in view. A test
that passes ``expose=`` itself (even ``expose=()``, meaning "none") is not touched;
the headline tests in ``test_sandbox_root.py`` rely on that.
"""

from __future__ import annotations

import functools
import os
import sys
from collections.abc import Callable, Mapping

import pytest

from openplow.sandbox import UnshareSandbox

REQUIRE_SANDBOX = "OPENPLOW_REQUIRE_SANDBOX"


def _missing_sandbox(environ: Mapping[str, str], unshare_works: Callable[[], bool]) -> str | None:
    """Why the run must stop, when the real sandbox is required but cannot start.

    Every real-sandbox test skips when unprivileged user namespaces are unavailable,
    which is right on a laptop and wrong in CI: on GitHub's Ubuntu 24.04 runners
    AppArmor blocked them and all of those tests skipped while the run stayed green.
    CI sets ``OPENPLOW_REQUIRE_SANDBOX=1`` so a lost sandbox is a red run instead.
    """
    if environ.get(REQUIRE_SANDBOX) != "1" or unshare_works():
        return None
    return (f"{REQUIRE_SANDBOX}=1 but `unshare --user` cannot start a sandbox here, so "
            "every real-sandbox test would skip. On Ubuntu 23.10+ lift the AppArmor "
            "restriction: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")


def pytest_sessionstart(session):
    from test_sandbox_hardening import _unshare_works

    reason = _missing_sandbox(os.environ, _unshare_works)
    if reason:
        pytest.exit(reason, returncode=1)


def _interpreter_roots() -> tuple[str, ...]:
    """The test interpreter's install roots that the minimal root would not show."""
    candidates = (
        sys.prefix,
        sys.base_prefix,
        os.path.dirname(os.path.dirname(os.path.realpath(sys.executable))),
    )
    roots: list[str] = []
    for raw in candidates:
        path = os.path.realpath(raw)
        if path == "/" or path == "/usr" or path.startswith("/usr/"):
            continue  # "/" is refused by the launcher; /usr is already visible
        if not os.path.exists(path) or path in roots:
            continue
        roots.append(path)
    return tuple(roots)


@pytest.fixture(autouse=True, scope="session")
def _expose_the_test_interpreter():
    if not sys.platform.startswith("linux"):
        yield
        return
    roots = _interpreter_roots()
    original = UnshareSandbox.__init__

    @functools.wraps(original)
    def __init__(self, *args, **kwargs):
        if "expose" not in kwargs:  # an explicit expose, even (), is the caller's
            kwargs["expose"] = roots
        original(self, *args, **kwargs)

    mp = pytest.MonkeyPatch()
    mp.setattr(UnshareSandbox, "__init__", __init__)
    try:
        yield
    finally:
        mp.undo()
