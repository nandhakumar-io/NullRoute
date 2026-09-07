import uuid

from sqlalchemy import Column, DateTime, String, Text, func

from app.models.db import Base


class ComplianceBaseline(Base):
    """An approved-baseline configuration *template* shared by every device
    of a given role (e.g. "core", "access", "edge-firewall") -- the
    role-based counterpart to GoldenConfig, which is one-per-device.
    """

    __tablename__ = "compliance_baselines"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_role = Column(String, nullable=False, unique=True, index=True)

    config_encrypted = Column(Text, nullable=False)
    checksum = Column(String, nullable=False)
    set_by = Column(String, nullable=False, default="system")
    description = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
