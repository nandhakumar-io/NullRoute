import enum
import uuid

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Integer, Text, String, func

from app.models.db import Base


class DriftBaseline(str, enum.Enum):
    GOLDEN_CONFIG = "golden_config"
    PREVIOUS_BACKUP = "previous_backup"
    ROLE_BASELINE = "role_baseline"


class DriftSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DriftStatus(str, enum.Enum):
    OPEN = "open"
    APPROVED = "approved"
    ROLLED_BACK = "rolled_back"
    DISMISSED = "dismissed"


class ConfigDrift(Base):
    """A detected difference between a device's live running-config and a
    baseline (golden config or its own previous backup snapshot). Produced
    by app.services.drift_service.detect_drift, run nightly per-device by
    app.tasks.drift_detection_task and on-demand via
    GET /devices/{id}/drift.
    """

    __tablename__ = "config_drifts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)

    baseline = Column(Enum(DriftBaseline), nullable=False, default=DriftBaseline.PREVIOUS_BACKUP)
    diff_text = Column(Text, nullable=False)  # unified diff, same format as diff_engine.generate_diff
    added_lines = Column(Integer, nullable=False, default=0)
    removed_lines = Column(Integer, nullable=False, default=0)
    modified_lines = Column(Integer, nullable=False, default=0)

    risk_score = Column(Integer, nullable=False, default=0)  # 0-100, reuses risk_engine heuristics
    compliance_score = Column(Integer, nullable=False, default=100)  # 0-100, 100 = fully compliant
    severity = Column(Enum(DriftSeverity), nullable=False, default=DriftSeverity.LOW)

    ai_summary = Column(Text, nullable=True)  # human-readable findings, e.g. "ACL modified, VLAN removed"
    cli_diff = Column(Text, nullable=True)
    status = Column(Enum(DriftStatus), nullable=False, default=DriftStatus.OPEN)

    # In NetGuard, there was a maintenance_window_id foreign key. We'll add it as UUID without FK to avoid breaking things if table doesn't exist, though typically we should use FK if it exists. 
    maintenance_window_id = Column(String, nullable=True)

    unattributed = Column(Boolean, nullable=False, default=False)

    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

