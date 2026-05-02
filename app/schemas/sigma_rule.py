import uuid
from datetime import date as _date
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from app.models.sigma_rule import LevelEnum, StatusEnum


class SigmaRuleBase(BaseModel):
    title: str
    status: Optional[StatusEnum] = None
    description: Optional[str] = None
    license: Optional[str] = None
    author: Optional[str] = None
    date: Optional[_date] = None
    modified: Optional[_date] = None
    references: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    falsepositives: Optional[list[str]] = None
    level: Optional[LevelEnum] = None
    logsource_category: Optional[str] = None
    logsource_product: Optional[str] = None
    logsource_service: Optional[str] = None
    logsource_definition: Optional[str] = None
    detection: dict[str, Any]
    raw_rule: Optional[str] = None


class SigmaRuleCreate(SigmaRuleBase):
    # Accept the rule's own UUID so existing sigma IDs are preserved on import.
    id: Optional[uuid.UUID] = None


class SigmaRuleUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[StatusEnum] = None
    description: Optional[str] = None
    license: Optional[str] = None
    author: Optional[str] = None
    date: Optional[_date] = None
    modified: Optional[_date] = None
    references: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    falsepositives: Optional[list[str]] = None
    level: Optional[LevelEnum] = None
    logsource_category: Optional[str] = None
    logsource_product: Optional[str] = None
    logsource_service: Optional[str] = None
    logsource_definition: Optional[str] = None
    detection: Optional[dict[str, Any]] = None
    raw_rule: Optional[str] = None


class SigmaRuleResponse(SigmaRuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
