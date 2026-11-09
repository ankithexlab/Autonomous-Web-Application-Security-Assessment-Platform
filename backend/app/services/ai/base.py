"""
Base AI Provider Interface.
"""

from abc import ABC, abstractmethod

from app.schemas.ai import AIAnalysisInput, AIAnalysisOutput, AIRemediationOutput, ChatMessageInput


class BaseAIProvider(ABC):
    """Abstract base provider interface for AI analysis, remediation, and security chat."""

    @abstractmethod
    async def analyze_finding(self, input_data: AIAnalysisInput) -> AIAnalysisOutput:
        """Analyze a verified vulnerability finding."""
        pass

    @abstractmethod
    async def generate_remediation(self, input_data: AIAnalysisInput) -> AIRemediationOutput:
        """Generate structured remediation guidance and secure code examples."""
        pass

    @abstractmethod
    async def chat_completion(
        self,
        messages: list[ChatMessageInput],
        system_instruction: str | None = None,
    ) -> str:
        """Generate a chat response to user query."""
        pass
