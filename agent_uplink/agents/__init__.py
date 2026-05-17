from .base import Agent
from .claude.agent import ClaudeAgent

AGENTS: dict[str, type[Agent]] = {ClaudeAgent.name: ClaudeAgent}

__all__ = ["AGENTS", "Agent", "ClaudeAgent"]
