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

import pytest

from openplow.sandbox import UnshareSandbox


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
