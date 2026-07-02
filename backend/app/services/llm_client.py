from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class LLMResult:
    enabled: bool
    provider: str
    model: str
    raw_text: str = ""
    parsed_json: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class LLMClient:
    def __init__(self) -> None:
        self.provider = os.getenv("LLM_PROVIDER", "rule").lower().strip()
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.timeout = int(os.getenv("LLM_TIMEOUT_SECONDS", "45"))

    def is_enabled(self, request_override: bool | None = None) -> bool:
        if request_override is not None:
            return bool(request_override)
        return os.getenv("USE_LLM", "false").lower() in {"1", "true", "yes", "on"}

    def analyze_json(self, system_prompt: str, user_prompt: str, request_override: bool | None = None) -> LLMResult:
        if not self.is_enabled(request_override):
            return LLMResult(enabled=False, provider="rule", model="local-rules")
        if self.provider == "openai":
            return self._openai(system_prompt, user_prompt)
        if self.provider == "ollama":
            return self._ollama(system_prompt, user_prompt)
        return LLMResult(enabled=False, provider=self.provider, model="unknown", error="Unsupported LLM_PROVIDER. Use rule, openai, or ollama.")

    def _openai(self, system_prompt: str, user_prompt: str) -> LLMResult:
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return LLMResult(enabled=False, provider="openai", model=self.openai_model, error="OPENAI_API_KEY is missing")
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": self.openai_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            text = response.json()["choices"][0]["message"]["content"]
            return LLMResult(enabled=True, provider="openai", model=self.openai_model, raw_text=text, parsed_json=self._parse_json(text))
        except Exception as exc:  # noqa: BLE001
            return LLMResult(enabled=False, provider="openai", model=self.openai_model, error=str(exc))

    def _ollama(self, system_prompt: str, user_prompt: str) -> LLMResult:
        try:
            response = requests.post(
                f"{self.ollama_base_url.rstrip('/')}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.2},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            text = response.json().get("message", {}).get("content", "")
            return LLMResult(enabled=True, provider="ollama", model=self.ollama_model, raw_text=text, parsed_json=self._parse_json(text))
        except Exception as exc:  # noqa: BLE001
            return LLMResult(enabled=False, provider="ollama", model=self.ollama_model, error=str(exc))

    @staticmethod
    def _parse_json(text: str) -> Dict[str, Any] | None:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    return None
            return None
