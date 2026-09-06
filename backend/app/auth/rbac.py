"""Section 11/security-improvements RBAC matrix.

Explicit roles and permissions, enforced server-side on every route that
needs it (never relying on the frontend hiding a button — see
frontend/src/components/ui.tsx `Can` / `useHasPermission` for the UI-side
mirror of this same matrix, which only *hides* affordances; the real
enforcement is here).

Roles
-----
SUPER_ADMIN      -- cross-tenant platform operator (all permissions, all
                    tenants). Reserved for Anthropic/vendor ops, not normal
                    customer users.
TENANT_ADMIN     -- full control within their own tenant.
SECURITY_ANALYST -- reviews findings, approves AI mappings and remediation.
AUDITOR          -- read-only + audit log access. Cannot change state.
OPERATOR         -- runs scans, manages devices/credentials, day-to-day ops.
VIEWER           -- read-only dashboards/reports.

Backward compatibility
-----------------------
The original (pre-Section-11) role set shipped by this app was the lowercase
Keycloak role names {admin, security_analyst, operator, auditor, viewer}.
Those are still accepted from JWTs and mapped onto the new roles below so
existing Keycloak realm configuration keeps working without a re-issue of
tokens; `admin` maps to TENANT_ADMIN (tenant-scoped, not cross-tenant).
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet


class Role(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AUDITOR = "AUDITOR"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    SCAN = "scan"                              # trigger/re-run scans, upload configs
    VIEW = "view"                               # read dashboards, findings, devices, reports
    EXPORT = "export"                           # download reports / evidence
    APPROVE_AI_MAPPING = "approve_ai_mapping"   # Training Center approve/reject
    MODIFY_BASELINE = "modify_baseline"         # edit compliance baselines/frameworks mappings
    APPROVE_REMEDIATION = "approve_remediation" # change-request / exception approve-reject
    MANAGE_USERS = "manage_users"                # user/role administration
    MANAGE_CREDENTIALS = "manage_credentials"   # device credential refs (create/rotate/delete)
    MANAGE_FRAMEWORKS = "manage_frameworks"     # compliance framework configuration
    VIEW_AUDIT_LOG = "view_audit_log"           # read the audit trail


# Legacy Keycloak realm role names -> new canonical role. Anything not in
# this map is assumed to already be a canonical Role value.
LEGACY_ROLE_ALIASES: Dict[str, Role] = {
    "admin": Role.TENANT_ADMIN,
    "security_analyst": Role.SECURITY_ANALYST,
    "operator": Role.OPERATOR,
    "auditor": Role.AUDITOR,
    "viewer": Role.VIEWER,
}

ALL_ROLE_NAMES = [r.value for r in Role] + list(LEGACY_ROLE_ALIASES.keys())


ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.SUPER_ADMIN: frozenset(p for p in Permission),
    Role.TENANT_ADMIN: frozenset(p for p in Permission),  # full control, own tenant only
    Role.SECURITY_ANALYST: frozenset({
        Permission.VIEW,
        Permission.EXPORT,
        Permission.APPROVE_AI_MAPPING,
        Permission.MODIFY_BASELINE,
        Permission.APPROVE_REMEDIATION,
    }),
    Role.AUDITOR: frozenset({
        Permission.VIEW,
        Permission.EXPORT,
        Permission.VIEW_AUDIT_LOG,
    }),
    Role.OPERATOR: frozenset({
        Permission.SCAN,
        Permission.VIEW,
        Permission.EXPORT,
        Permission.MANAGE_CREDENTIALS,
    }),
    Role.VIEWER: frozenset({
        Permission.VIEW,
    }),
}


def normalize_role(raw: str) -> Role | None:
    if raw in LEGACY_ROLE_ALIASES:
        return LEGACY_ROLE_ALIASES[raw]
    try:
        return Role(raw)
    except ValueError:
        return None


def permissions_for(roles: list[str]) -> FrozenSet[Permission]:
    perms: set[Permission] = set()
    for raw in roles:
        role = normalize_role(raw)
        if role:
            perms |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(perms)


def has_permission(roles: list[str], *required: Permission) -> bool:
    """True if the role set grants ANY of the required permissions."""
    granted = permissions_for(roles)
    return any(p in granted for p in required)