"""
Crucible model registry.

get_model(tier_config) returns a cached LangChain chat model for the given
tier configuration dict (from crucible_config.json escalation_chain).

Supported providers:
  ollama, anthropic, openai, groq, mistral, deepseek, openrouter, together, google
"""

import os
from functools import lru_cache
from typing import Any, Dict

from dotenv import load_dotenv

load_dotenv(override=False)
_private_env = os.path.join(os.path.dirname(__file__), "..", ".private.env")
if os.path.exists(_private_env):
    load_dotenv(_private_env, override=True)


# Strip /v1 suffix that some UIs append to Ollama URLs
_OLLAMA_HOST = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").removesuffix("/v1")


def _tier_cache_key(tier_cfg: Dict[str, Any]) -> str:
    """Stable string key for lru_cache from a tier config dict."""
    return f"{tier_cfg['provider']}::{tier_cfg['model']}::{tier_cfg.get('temperature', 0.1)}::{tier_cfg.get('max_tokens', 4096)}"


_model_cache: Dict[str, Any] = {}


def get_model(tier_cfg: Dict[str, Any]) -> Any:
    """
    Return a LangChain chat model for the given tier config.
    Results are cached — one instance per unique (provider, model, temperature, max_tokens).
    """
    key = _tier_cache_key(tier_cfg)
    if key in _model_cache:
        return _model_cache[key]

    provider = tier_cfg["provider"]
    model = tier_cfg["model"]
    temperature = tier_cfg.get("temperature", 0.1)
    max_tokens = tier_cfg.get("max_tokens", 4096)

    instance = _build_model(provider, model, temperature, max_tokens)
    _model_cache[key] = instance
    return instance


def _build_model(provider: str, model: str, temperature: float, max_tokens: int) -> Any:
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=model,
            base_url=_OLLAMA_HOST,
            temperature=temperature,
            num_predict=max_tokens,
            think=False,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model,
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=os.getenv("OPENAI_API_KEY"),
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "groq":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=os.getenv("GROQ_API_KEY"),
            base_url="https://api.groq.com/openai/v1",
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "mistral":
        from langchain_mistralai import ChatMistralAI
        return ChatMistralAI(
            model=model,
            api_key=os.getenv("MISTRAL_API_KEY"),
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "deepseek":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com/v1",
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "openrouter":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "together":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=os.getenv("TOGETHER_API_KEY"),
            base_url="https://api.together.xyz/v1",
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "deepinfra":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=os.getenv("DEEPINFRA_API_KEY"),
            base_url="https://api.deepinfra.com/v1/openai",
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=model,
            google_api_key=os.getenv("GOOGLE_API_KEY"),
            temperature=temperature,
            max_output_tokens=max_tokens,
        )

    raise ValueError(f"Unknown provider: {provider!r}. "
                     f"Supported: ollama, anthropic, openai, groq, mistral, "
                     f"deepseek, openrouter, together, google, deepinfra")
