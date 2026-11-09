"""
AI Analysis & Assistant API endpoints.

Routes:
  POST /api/v1/ai/findings/{finding_id}/analyze — Analyze a vulnerability finding
  POST /api/v1/ai/chat — Interactive security assistant chat endpoint
  GET  /api/v1/ai/status — AI engine configuration and provider status
"""

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.ai import (
    AIAnalysisOutput,
    AIRemediationOutput,
    AIStatusOutput,
    ChatRequest,
    ChatResponse,
)
from app.services.ai.service import AIService

router = APIRouter(prefix="/ai", tags=["AI Security Engine"])


@router.post(
    "/findings/{finding_id}/analyze",
    response_model=AIAnalysisOutput,
    summary="Generate structured AI analysis and remediation advice for a finding",
)
async def analyze_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AIAnalysisOutput:
    service = AIService(db)
    return await service.analyze_finding_by_id(finding_id, current_user.id)


@router.post(
    "/findings/{finding_id}/remediation",
    response_model=AIRemediationOutput,
    summary="Generate structured technology-aware remediation plan and secure code example",
)
async def generate_remediation(
    finding_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AIRemediationOutput:
    service = AIService(db)
    return await service.get_remediation_by_id(finding_id, current_user.id)


@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Interactive AI security assistant session",
)
async def chat_assistant(
    payload: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ChatResponse:
    service = AIService(db)
    reply_text, attached_contexts = await service.chat(
        payload.messages,
        user_id=current_user.id,
        finding_id=payload.finding_id,
        scan_id=payload.scan_id,
        target_id=payload.target_id,
        report_id=payload.report_id,
    )

    # Extract code blocks if formatted with ```
    import re
    code_blocks = []
    matches = re.findall(r"```(\w+)?\n(.*?)```", reply_text, re.DOTALL)
    for lang, code in matches:
        code_blocks.append({"language": lang or "text", "code": code.strip()})

    settings = get_settings()
    return ChatResponse(
        reply=reply_text,
        code_blocks=code_blocks,
        provider=settings.AI_PROVIDER,
        model=settings.AI_MODEL_NAME,
        is_advisory=True,
        context_attached=attached_contexts,
    )


@router.get(
    "/status",
    response_model=AIStatusOutput,
    summary="Get active AI provider status and engine configuration",
)
async def get_ai_status(
    current_user: User = Depends(get_current_user),
) -> AIStatusOutput:
    settings = get_settings()
    if settings.AI_PROVIDER == "gemini":
        has_api_key = bool(settings.effective_gemini_api_key)
    elif settings.AI_PROVIDER == "openai":
        has_api_key = bool(settings.effective_openai_api_key)
    else:
        has_api_key = True
    status_str = "online" if (has_api_key or settings.AI_PROVIDER == "mock") else "key_missing"

    return AIStatusOutput(
        status=status_str,
        provider=settings.AI_PROVIDER,
        model=settings.AI_MODEL_NAME,
        timeout_seconds=settings.AI_TIMEOUT_SECONDS,
        has_api_key=has_api_key,
        rate_limit_per_minute=settings.AI_MAX_REQUESTS_PER_MINUTE,
        max_tokens=settings.AI_MAX_TOKENS,
        features={
            "finding_analysis": True,
            "remediation_guidance": True,
            "interactive_chat": True,
            "live_context_retrieval": True,
            "prompt_injection_defense": True,
            "evidence_sanitization": True,
        },
    )

