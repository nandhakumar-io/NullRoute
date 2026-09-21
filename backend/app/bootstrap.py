"""Creates the first local admin account on startup, so a fresh deployment
with AUTH_ENABLED=true and no Keycloak configured still has a way to log
in.

Idempotent: does nothing once ANY user row exists. Attaches the bootstrap
admin to the existing SIH-Demo tenant (see auth/dependencies.py
DEMO_TENANT_NAME) so pre-seeded demo data stays visible after auth is
turned on.

Configuration:
    BOOTSTRAP_ADMIN_USERNAME   default "admin"
    BOOTSTRAP_ADMIN_PASSWORD   if set, used verbatim (must still pass the
                               MIN_PASSWORD_LENGTH check).
                               If unset, a random password is generated and
                               printed to the log ONCE -- it is not
                               recoverable afterwards; delete the user row
                               and restart to get a new one.
"""
from __future__ import annotations

import logging
import os
import secrets

logger = logging.getLogger("app.auth.bootstrap")

DEFAULT_BOOTSTRAP_USERNAME = "admin"


def _generate_password() -> str:
    # 24 chars of urlsafe base64 (~18 bytes of entropy) -- comfortably over
    # MIN_PASSWORD_LENGTH and doesn't need shift-key gymnastics to type.
    return secrets.token_urlsafe(18)


def ensure_bootstrap_admin() -> None:
    """Call once at startup, after init_db(). Safe to call every boot."""
    from app.auth.dependencies import DEMO_TENANT_NAME
    from app.auth.passwords import hash_password
    from app.db import SessionLocal
    from app.models.db import Tenant, User

    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return  # already bootstrapped (or an admin manages users now)

        tenant = db.query(Tenant).filter(Tenant.name == DEMO_TENANT_NAME).first()
        if not tenant:
            tenant = Tenant(name=DEMO_TENANT_NAME)
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", DEFAULT_BOOTSTRAP_USERNAME).strip() or DEFAULT_BOOTSTRAP_USERNAME
        password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "").strip()
        generated = False
        if not password:
            password = _generate_password()
            generated = True

        user = User(
            tenant_id=tenant.id,
            username=username,
            password_hash=hash_password(password),
            roles=["admin"],
            is_active=True,
        )
        db.add(user)
        db.commit()

        if generated:
            logger.warning(
                "Bootstrap admin created: username=%r password=%r "
                "(tenant=%r). This password is shown ONLY this once -- "
                "store it now. Set BOOTSTRAP_ADMIN_PASSWORD to control it "
                "on the next fresh deployment instead of relying on this "
                "log line.",
                username, password, tenant.name,
            )
        else:
            logger.info(
                "Bootstrap admin created: username=%r (tenant=%r), "
                "password from BOOTSTRAP_ADMIN_PASSWORD.",
                username, tenant.name,
            )
    except Exception:  # noqa: BLE001 - never block API startup on this
        logger.exception("Bootstrap admin creation failed")
        db.rollback()
    finally:
        db.close()