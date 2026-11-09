"""
AI Pydantic Schemas.

Defines structured inputs and output response format for AI analysis and assistant.
"""

from pydantic import BaseModel, ConfigDict, Field


class AIAnalysisInput(BaseModel):
    title: str
    severity: str
    confidence: str
    category: str
    owasp_category: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    affected_url: str | None = None
    description: str | None = None
    proof_of_concept: str | None = None


class AIAnalysisOutput(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    summary: str = Field(description="Concise summary of the vulnerability")
    risk_explanation: str = Field(description="Detailed explanation of risk")
    impact: str = Field(description="Potential business and security impact")
    why_it_matters: str = Field(description="Contextual importance")
    remediation_guidance: list[str] = Field(description="Step-by-step remediation instructions")
    secure_code_example: str | None = Field(default=None, description="Secure implementation code snippet")
    confidence: str = Field(default="HIGH", description="Analysis confidence level")
    limitations: list[str] = Field(default_factory=list, description="Analysis assumptions or constraints")


class AIRemediationOutput(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    remediation_summary: str = Field(description="High level remediation summary")
    root_cause: str = Field(description="Underlying root cause analysis")
    recommended_fix: str = Field(description="Recommended solution")
    implementation_steps: list[str] = Field(description="Step-by-step developer remediation instructions")
    secure_configuration_example: str | None = Field(default=None, description="Configuration fix snippet")
    secure_code_example: str | None = Field(default=None, description="Secure code fix snippet")
    affected_component: str | None = Field(default=None, description="Identified affected technology or header")
    verification_steps: list[str] = Field(description="Steps to verify fix effectiveness")
    limitations: list[str] = Field(default_factory=list, description="Remediation constraints or assumptions")
    confidence: str = Field(default="HIGH", description="Remediation confidence rating")


class ChatMessageInput(BaseModel):
    role: str  # "user", "assistant", "system"
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessageInput]
    finding_id: str | None = None
    scan_id: str | None = None
    target_id: str | None = None
    report_id: str | None = None


class ChatResponse(BaseModel):
    reply: str
    code_blocks: list[dict[str, str]] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    is_advisory: bool = True
    context_attached: list[str] = Field(default_factory=list)


class AIStatusOutput(BaseModel):
    status: str
    provider: str
    model: str
    timeout_seconds: int
    has_api_key: bool
    rate_limit_per_minute: int = 30
    max_tokens: int = 2048
    features: dict[str, bool] = Field(default_factory=dict)

