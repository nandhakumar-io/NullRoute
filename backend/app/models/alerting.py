"""Enterprise alerting configuration (channels, routing rules, push subs).

Historically alert_service.py dispatched to a single, environment-variable
configured webhook/ntfy/SMTP destination for the whole deployment. This
module adds real per-tenant configuration on top of that: operators can
define any number of named AlertChannel rows (email / ntfy / webhook /
push), then AlertRule rows that decide which channels a given
category/severity combination is routed to. The legacy env-var
destinations in alert_service.py keep working unchanged as a
deployment-wide fallback (RULE: never remove a working delivery path),
these tables are purely additive.

Secret material (SMTP password, ntfy auth token, webhook signing secret)
follows the existing OpenBao convention (RULE 6) via `credential_ref` --
this table only ever stores non-secret connection config.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.models.db import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


CHANNEL_TYPES = ("email", "ntfy", "webhook", "push")


class AlertChannel(Base):
    """A configured notification destination. `channel_type` is one of
    "email" | "ntfy" | "webhook" | "push".

    config shape by type:
      email:   {smtp_host, smtp_port, use_tls, from_address, to_addresses:[...]}
      ntfy:    {server_url (e.g. https://ntfy.sh), topic, priority, tags:[...]}
      webhook: {url, headers: {...}}
      push:    {} -- push has no per-channel config; it fans out to every
               PushSubscription row owned by the tenant.
    """

    __tablename__ = "alert_channels"

    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    channel_type = Column(String, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    config = Column(JSON, nullable=False, default=dict)

    # Secret material (e.g. SMTP config) used to be an OpenBao ref.
    secret_data = Column(JSON, nullable=True)

    last_test_status = Column(String, nullable=True)  # SUCCESS | FAILED | NEVER_TESTED
    last_test_at = Column(DateTime, nullable=True)
    last_test_message = Column(Text, nullable=True)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AlertRule(Base):
    """Routing rule: which channels get notified for which
    categories/severities. `match_categories`/`match_severities` of None
    (or empty list) means "match everything" for that dimension, so a
    single catch-all rule is just {categories: [], severities: []}.
    """

    __tablename__ = "alert_rules"

    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    match_categories = Column(JSON, nullable=True)  # list[str] | null = all categories
    match_severities = Column(JSON, nullable=True)  # list[str] | null = all severities
    channel_ids = Column(JSON, nullable=False, default=list)
    # Quiet hours / throttling, informational for now, honored best-effort
    # by the dispatcher: {"min_severity_for_push": "HIGH"} etc.
    options = Column(JSON, nullable=True)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PushSubscription(Base):
    """One browser/device Web Push subscription (per RFC 8030), created via
    the frontend's Notification/PushManager API and registered through
    POST /api/alerts/push/subscribe. Endpoint is the whole-subscription
    unique key -- re-subscribing the same browser updates rather than
    duplicates the row.
    """

    __tablename__ = "push_subscriptions"

    id = Column(String, primary_key=True, default=gen_uuid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    user_subject = Column(String, nullable=True)
    endpoint = Column(Text, nullable=False, unique=True)
    p256dh = Column(String, nullable=False)
    auth = Column(String, nullable=False)
    user_agent = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)