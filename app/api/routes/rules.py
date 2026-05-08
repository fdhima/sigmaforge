import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import cast, or_, select, String
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.database import get_session
from app.models.sigma_rule import LevelEnum, SigmaRule, StatusEnum
from app.schemas.sigma_rule import (
    RuleConversionResponse,
    SigmaRuleCreate,
    SigmaRuleResponse,
    SigmaRuleUpdate,
)
from app.services.sigma_parser import (
    SigmaConversionError,
    SigmaParseError,
    convert_to_query,
    list_backends,
)

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("/backends", response_model=list[str])
async def get_backends() -> list[str]:
    """List all available Sigma backends."""
    return list_backends()


@router.post("/", response_model=SigmaRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: SigmaRuleCreate,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(get_current_user),
) -> SigmaRule:
    data = body.model_dump(exclude_none=True)
    rule = SigmaRule(**data)
    session.add(rule)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Sigma rule with id {rule.id} already exists",
        )
    await session.refresh(rule)
    return rule


@router.get("/", response_model=list[SigmaRuleResponse])
async def list_rules(
    q: str | None = Query(None, description="Full-text search across title, description, author, and tags"),
    status: StatusEnum | None = Query(None),
    level: LevelEnum | None = Query(None),
    product: str | None = Query(None),
    category: str | None = Query(None),
    service: str | None = Query(None),
    tag: str | None = Query(None, description="Filter rules that contain this tag"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> list[SigmaRule]:
    stmt = select(SigmaRule)

    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            or_(
                SigmaRule.title.ilike(pattern),
                SigmaRule.description.ilike(pattern),
                SigmaRule.author.ilike(pattern),
                # Cast ARRAY to text for a simple contains check
                cast(SigmaRule.tags, String).ilike(pattern),
            )
        )
    if status:
        stmt = stmt.where(SigmaRule.status == status)
    if level:
        stmt = stmt.where(SigmaRule.level == level)
    if product:
        stmt = stmt.where(SigmaRule.logsource_product.ilike(f"%{product}%"))
    if category:
        stmt = stmt.where(SigmaRule.logsource_category.ilike(f"%{category}%"))
    if service:
        stmt = stmt.where(SigmaRule.logsource_service.ilike(f"%{service}%"))
    if tag:
        # PostgreSQL ARRAY contains operator
        stmt = stmt.where(SigmaRule.tags.contains([tag]))

    stmt = stmt.order_by(SigmaRule.created_at.desc()).offset(offset).limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())


@router.get("/{rule_id}", response_model=SigmaRuleResponse)
async def get_rule(
    rule_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> SigmaRule:
    rule = await session.get(SigmaRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


@router.get("/{rule_id}/convert", response_model=RuleConversionResponse)
async def convert_rule(
    rule_id: uuid.UUID,
    backend: str = Query(..., description="The backend to convert the rule to"),
    pipelines: list[str] | None = Query(None, description="Optional processing pipelines"),
    session: AsyncSession = Depends(get_session),
) -> RuleConversionResponse:
    """Convert a stored Sigma rule to a backend-specific query."""
    rule = await session.get(SigmaRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    if not rule.raw_rule:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rule has no raw source to convert",
        )

    try:
        queries = convert_to_query(rule.raw_rule, backend, pipeline_names=pipelines)
        return RuleConversionResponse(rule_id=rule_id, backend=backend, queries=queries)
    except (SigmaConversionError, SigmaParseError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/{rule_id}", response_model=SigmaRuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    body: SigmaRuleUpdate,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(get_current_user),
) -> SigmaRule:
    rule = await session.get(SigmaRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)

    await session.commit()
    await session.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(get_current_user),
) -> None:
    rule = await session.get(SigmaRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    await session.delete(rule)
    await session.commit()
