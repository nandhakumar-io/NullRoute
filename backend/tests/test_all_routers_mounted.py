"""Regression test for the "fully-built router that's never wired into
app/main.py" class of bug (bit this codebase twice now -- most recently
app/routers/custom_controls.py: a complete, correct CRUD + approval router
whose endpoints were all live 404s because nobody added the
`app.include_router(custom_controls.router)` line).

This walks every module under app/routers/ that exposes a `router`
(APIRouter) attribute, and asserts each of its route paths is actually
present on the running `app.main.app`. A router module that exists but was
never `include_router()`-ed into main.py now fails CI instead of silently
404ing in production.

Intentionally does NOT import app.main at module scope -- app.main reads
DATABASE_URL/CORS_ALLOWED_ORIGINS etc. at import time, so it's imported
inside the test after the env is set up, matching the pattern the rest of
the suite uses.
"""
from __future__ import annotations

import importlib
import pkgutil

import app.routers as routers_pkg

# Files in app/routers/ that are not route modules (no `router` attribute)
# and should not be expected to register anything.
_NON_ROUTER_MODULES = {"__init__", "schemas"}


def _discover_router_modules():
    names = []
    for _, module_name, _ in pkgutil.iter_modules(routers_pkg.__path__):
        if module_name in _NON_ROUTER_MODULES:
            continue
        names.append(module_name)
    return sorted(names)


def test_every_router_module_is_mounted(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_ENABLED", "false")

    from app.main import app

    mounted_paths = {route.path for route in app.routes}

    module_names = _discover_router_modules()
    assert module_names, "expected to discover at least one router module"

    missing = {}
    for module_name in module_names:
        module = importlib.import_module(f"app.routers.{module_name}")
        router = getattr(module, "router", None)
        if router is None:
            # A router module with no `router` attribute is itself
            # suspicious enough to flag rather than silently skip.
            missing[module_name] = ["<no `router` attribute on module>"]
            continue

        unmounted = [r.path for r in router.routes if r.path not in mounted_paths]
        if unmounted:
            missing[module_name] = unmounted

    assert not missing, (
        "The following router modules have routes that are not mounted on "
        "app.main.app -- add the missing app.include_router(...) call(s) "
        f"in app/main.py: {missing}"
    )