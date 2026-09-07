import uuid

from sqlalchemy import Column, DateTime, ForeignKey, String, Text, func

from app.models.db import Base


class GoldenConfig(Base):
    """The authoritative, approved-baseline configuration for a device.

    One row per device (device_id is unique). Used as the comparison
    target for Configuration Management (GET/PUT .../golden-config,
    POST .../compare) and for Drift Detection when
    ConfigDrift.baseline == DriftBaseline.GOLDEN_CONFIG.
    """

    __tablename__ = "golden_configs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    config_encrypted = Column(Text, nullable=False)
    checksum = Column(String, nullable=False)
    set_by = Column(String, nullable=False, default="system")

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
