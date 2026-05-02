import enum
import uuid
from datetime import date as _date
from datetime import datetime
from typing import Optional

from sqlalchemy import Date, DateTime, Enum as SAEnum, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class StatusEnum(str, enum.Enum):
    stable = "stable"
    test = "test"
    experimental = "experimental"
    deprecated = "deprecated"
    unsupported = "unsupported"


class LevelEnum(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class SigmaRule(Base):
    __tablename__ = "sigma_rules"

    # --- Identity ---
    # Uses the sigma rule's own UUID when provided; generates one otherwise.
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # --- Required metadata ---
    title: Mapped[str] = mapped_column(String(256), nullable=False)

    # --- Optional metadata ---
    status: Mapped[Optional[StatusEnum]] = mapped_column(SAEnum(StatusEnum, name="sigma_status"), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    license: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    author: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    date: Mapped[Optional[_date]] = mapped_column(Date, nullable=True)
    modified: Mapped[Optional[_date]] = mapped_column(Date, nullable=True)
    references: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text), nullable=True)
    tags: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text), nullable=True)
    falsepositives: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text), nullable=True)
    level: Mapped[Optional[LevelEnum]] = mapped_column(SAEnum(LevelEnum, name="sigma_level"), nullable=True)

    # --- Logsource (single logsource block per rule) ---
    logsource_category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    logsource_product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    logsource_service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    logsource_definition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # --- Detection (arbitrary YAML structure: selections, keywords, condition, timeframe) ---
    detection: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # --- Raw YAML source for round-trip fidelity ---
    raw_rule: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # --- Audit timestamps ---
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
