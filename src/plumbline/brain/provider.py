"""LLM Provider abstraction and concrete adapters."""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Protocol

import httpx

from plumbline.config import LLMConfig


class LLMProvider(Protocol):
    """Protocol for LLM communication."""

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        json_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Send completion request to the model."""
        ...


class MockProvider:
    """Deterministic mock provider for offline testing and benchmarking."""

    def __init__(
        self,
        canned_responses: Optional[list[dict[str, Any]]] = None,
        default_verdict: str = "confirm",
    ) -> None:
        self.canned_responses = list(canned_responses) if canned_responses else []
        self.default_verdict = default_verdict
        self.history: list[dict[str, Any]] = []

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        json_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        self.history.append({"messages": messages, "tools": tools})

        if self.canned_responses:
            return self.canned_responses.pop(0)

        # Check if last message is a tool response
        last_msg = messages[-1] if messages else {}
        if last_msg.get("role") == "tool":
            # Return final json after tool execution
            return {
                "content": json.dumps(
                    {
                        "verdict": self.default_verdict,
                        "confidence": "high",
                        "rationale": "Verified through deterministic mock evaluation.",
                        "fix_patch": None,
                    }
                ),
                "tool_calls": [],
                "usage": {"prompt_tokens": 150, "completion_tokens": 30, "total_tokens": 180},
                "model": "mock-brain",
            }

        # If tools provided and not called yet, call read_file once to exercise tool loop
        if tools and len(messages) <= 2:
            return {
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_mock_1",
                        "name": "read_file",
                        "args": {"path": "src/sample.py", "start": 1, "end": 10},
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
                "model": "mock-brain",
            }

        # Otherwise return direct JSON verdict
        return {
            "content": json.dumps(
                {
                    "verdict": self.default_verdict,
                    "confidence": "high",
                    "rationale": "Verified finding context deterministically.",
                    "fix_patch": None,
                }
            ),
            "tool_calls": [],
            "usage": {"prompt_tokens": 120, "completion_tokens": 25, "total_tokens": 145},
            "model": "mock-brain",
        }


class OpenAIProvider:
    """Provider for OpenAI and OpenAI-compatible APIs (Ollama, vLLM, Groq, OpenRouter)."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.api_key = os.environ.get(config.api_key_env, "")
        self.base_url = (config.base_url or "https://api.openai.com/v1").rstrip("/")
        self.model = config.model

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        json_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
        }

        if tools:
            payload["tools"] = tools

        if json_schema:
            payload["response_format"] = {"type": "json_object"}

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]["message"]
        tool_calls: list[dict[str, Any]] = []
        if "tool_calls" in choice and choice["tool_calls"]:
            for tc in choice["tool_calls"]:
                try:
                    args = json.loads(tc["function"]["arguments"])
                except Exception:
                    args = {}
                tool_calls.append(
                    {
                        "id": tc.get("id", ""),
                        "name": tc["function"]["name"],
                        "args": args,
                    }
                )

        usage = data.get("usage", {})
        return {
            "content": choice.get("content"),
            "tool_calls": tool_calls,
            "usage": {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            "model": self.model,
        }


class AnthropicProvider:
    """Provider for Anthropic Claude models."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.api_key = os.environ.get(config.api_key_env, "")
        self.model = config.model or "claude-3-5-sonnet-20241022"

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        json_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        # Extract system prompt if present
        system_text = ""
        user_assistant_messages: list[dict[str, Any]] = []
        for m in messages:
            if m.get("role") == "system":
                system_text = m.get("content", "")
            else:
                user_assistant_messages.append(m)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": user_assistant_messages,
            "max_tokens": 1024,
            "temperature": 0.0,
        }
        if system_text:
            payload["system"] = system_text

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                "https://api.anthropic.com/v1/messages", headers=headers, json=payload
            )
            resp.raise_for_status()
            data = resp.json()

        text_content = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text_content += block.get("text", "")

        usage = data.get("usage", {})
        return {
            "content": text_content,
            "tool_calls": [],
            "usage": {
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
                "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            },
            "model": self.model,
        }


class GeminiProvider:
    """Provider for Google Gemini models via REST API."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.api_key = os.environ.get(config.api_key_env, "")
        self.model = config.model or "gemini-1.5-flash"

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        json_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        contents: list[dict[str, Any]] = []
        for m in messages:
            role = "user" if m.get("role") in ("user", "system") else "model"
            contents.append({"role": role, "parts": [{"text": str(m.get("content", ""))}]})

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": 0.0},
        }

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        text_out = ""
        try:
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    text_out = parts[0].get("text", "")
        except Exception:
            pass

        return {
            "content": text_out,
            "tool_calls": [],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            "model": self.model,
        }


def create_provider(config: LLMConfig) -> LLMProvider:
    """Factory creating the appropriate LLM provider."""
    p = config.provider.lower()
    # plumbline:ignore[SLP002] Intentional mock provider selection for offline testing
    if p == "mock":
        return MockProvider()
    elif p in ("openai", "compat"):
        return OpenAIProvider(config)
    elif p == "anthropic":
        return AnthropicProvider(config)
    elif p == "gemini":
        return GeminiProvider(config)
    else:
        # Fall back to OpenAI compatible
        return OpenAIProvider(config)
