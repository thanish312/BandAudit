from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Literal, Protocol

from app.models import ProviderDiagnostics


ProviderId = Literal["aiml", "featherless"]
ChatMessage = dict[str, str]


class ProviderConfigurationError(RuntimeError):
    pass


class ProviderRequestError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


RETRYABLE_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}
DEFAULT_MAX_ATTEMPTS = 3
RETRY_BASE_DELAY_SECONDS = 0.8


class ChatCompletionProvider(Protocol):
    provider_id: ProviderId
    label: str

    @property
    def ready(self) -> bool:
        ...

    @property
    def model(self) -> str | None:
        ...

    @property
    def structured_output_mode(self) -> str:
        ...

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        max_tokens: int,
        temperature: float,
        model: str | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        ...

    def diagnostics(self) -> ProviderDiagnostics:
        ...


class OpenAICompatibleChatCompletionProvider:
    def __init__(
        self,
        *,
        provider_id: ProviderId,
        label: str,
        api_key_env_names: tuple[str, ...],
        base_url_env_name: str,
        model_env_names: tuple[str, ...],
        default_base_url: str,
        timeout_seconds: float,
    ) -> None:
        self.provider_id = provider_id
        self.label = label
        self._api_key_env_names = api_key_env_names
        self._base_url_env_name = base_url_env_name
        self._model_env_names = model_env_names
        self._default_base_url = default_base_url
        self._timeout_seconds = timeout_seconds
        self._last_error: str | None = None
        self._last_structured_output_mode = "none"

    @property
    def api_key(self) -> str | None:
        for name in self._api_key_env_names:
            value = os.getenv(name)
            if value:
                return value
        return None

    @property
    def base_url(self) -> str:
        return (os.getenv(self._base_url_env_name) or self._default_base_url).rstrip("/")

    @property
    def chat_completions_url(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    @property
    def model(self) -> str | None:
        for name in self._model_env_names:
            value = os.getenv(name)
            if value:
                return value
        return None

    @property
    def structured_output_mode(self) -> str:
        return self._last_structured_output_mode

    @property
    def ready(self) -> bool:
        return bool(self.api_key and self.model)

    def complete(
        self,
        *,
        messages: list[ChatMessage],
        max_tokens: int,
        temperature: float,
        model: str | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> str:
        if not self.api_key:
            self._last_error = f"{self.label} API key is not configured"
            raise ProviderConfigurationError(self._last_error)
        selected_model = model or self.model
        if not selected_model:
            self._last_error = f"{self.label} model is not configured"
            raise ProviderConfigurationError(self._last_error)

        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format is not None:
            payload["response_format"] = response_format

        try:
            self._last_structured_output_mode = str(response_format.get("type", "custom")) if response_format else "none"
            content = self._post_chat_completion_with_retry(payload)
        except ProviderRequestError as error:
            if response_format is not None and error.status_code in {400, 422}:
                retry_payload = dict(payload)
                retry_payload.pop("response_format", None)
                self._last_structured_output_mode = "downgraded_no_response_format"
                content = self._post_chat_completion_with_retry(retry_payload)
            else:
                raise

        self._last_error = None
        return content

    def diagnostics(self) -> ProviderDiagnostics:
        if self.ready:
            self._last_error = None
            status = "ready"
        else:
            status = "missing_configuration"

        return ProviderDiagnostics(
            provider=self.provider_id,
            label=self.label,
            status=status,
            api_key_present=bool(self.api_key),
            model_configured=bool(self.model),
            base_url=self.base_url,
            model=self.model,
            last_error=self._last_error,
        )

    def _post_chat_completion_with_retry(self, payload: dict[str, Any]) -> str:
        max_attempts = _max_provider_attempts()
        last_error: ProviderRequestError | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return self._post_chat_completion(payload)
            except ProviderRequestError as error:
                last_error = error
                if attempt >= max_attempts or not _retryable_provider_error(error):
                    raise
                time.sleep(RETRY_BASE_DELAY_SECONDS * attempt)

        if last_error is not None:
            raise last_error
        raise ProviderRequestError(f"{self.label} request failed before it was sent")

    def _post_chat_completion(self, payload: dict[str, Any]) -> str:
        request = urllib.request.Request(
            url=self.chat_completions_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "BandAudit/0.1",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")[:500]
            self._last_error = f"{self.label} request failed with HTTP {error.code}: {body}"
            raise ProviderRequestError(self._last_error, status_code=error.code) from error
        except (urllib.error.URLError, TimeoutError, socket.timeout) as error:
            self._last_error = f"{self.label} request failed: {error}"
            raise ProviderRequestError(self._last_error) from error

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as error:
            self._last_error = f"{self.label} returned invalid JSON"
            raise ProviderRequestError(self._last_error) from error

        content = _chat_completion_content(data)
        if not content:
            self._last_error = f"{self.label} returned an empty assistant message"
            raise ProviderRequestError(self._last_error)

        return content


def build_provider_registry(timeout_seconds: float) -> dict[ProviderId, ChatCompletionProvider]:
    return {
        "aiml": OpenAICompatibleChatCompletionProvider(
            provider_id="aiml",
            label="AI/ML API",
            api_key_env_names=("AIML_API_KEY", "AIMLAPI_API_KEY"),
            base_url_env_name="AIML_BASE_URL",
            model_env_names=("AIML_MODEL", "AIMLAPI_MODEL"),
            default_base_url="https://api.aimlapi.com/v1",
            timeout_seconds=timeout_seconds,
        ),
        "featherless": OpenAICompatibleChatCompletionProvider(
            provider_id="featherless",
            label="Featherless AI",
            api_key_env_names=("FEATHERLESS_API_KEY",),
            base_url_env_name="FEATHERLESS_BASE_URL",
            model_env_names=("FEATHERLESS_MODEL",),
            default_base_url="https://api.featherless.ai/v1",
            timeout_seconds=timeout_seconds,
        ),
    }


def _chat_completion_content(data: dict[str, Any]) -> str | None:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return None

    first = choices[0]
    if not isinstance(first, dict):
        return None

    message = first.get("message")
    if not isinstance(message, dict):
        return None

    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return None


def _retryable_provider_error(error: ProviderRequestError) -> bool:
    if error.status_code is None:
        return True
    return error.status_code in RETRYABLE_STATUS_CODES


def _max_provider_attempts() -> int:
    raw = os.getenv("BAND_PROVIDER_MAX_ATTEMPTS", "").strip()
    if not raw:
        return DEFAULT_MAX_ATTEMPTS
    try:
        return max(1, min(5, int(raw)))
    except ValueError:
        return DEFAULT_MAX_ATTEMPTS
