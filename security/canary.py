"""
Crucible canary credential generator.

Produces fake credentials that are format-identical to real ones.
Used in Deceptive mode: if exfiltrated code tries to use these keys,
the attempt will be logged as a confirmed threat.

All generated keys are stored in a registry for this session so that
outbound credential use in sandbox logs can be matched against them.
"""

import secrets
import string
from typing import Dict

# In-memory registry for the current process lifetime
_CANARY_REGISTRY: Dict[str, str] = {}


def _rand(length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_canary_credentials() -> Dict[str, str]:
    """
    Return a dict of fake credentials that mimic the format of real ones.
    All values are registered so they can be detected if seen in sandbox output.
    """
    creds = {
        # Anthropic key format: sk-ant-api03-<88 base64url chars>
        "ANTHROPIC_API_KEY": f"sk-ant-canary-{''.join(_rand(88, string.ascii_letters + string.digits + '-_'))}",

        # OpenAI key format: sk-proj-<48 chars>
        "OPENAI_API_KEY": f"sk-canary-{''.join(_rand(48))}",

        # Generic bearer-style token
        "GROQ_API_KEY": f"gsk_canary_{''.join(_rand(52))}",
        "MISTRAL_API_KEY": f"canary-{''.join(_rand(32))}",
        "DEEPSEEK_API_KEY": f"sk-canary-{''.join(_rand(32))}",
        "OPENROUTER_API_KEY": f"sk-or-canary-{''.join(_rand(40))}",
        "TOGETHER_API_KEY": f"canary-{''.join(_rand(40))}",
        "GOOGLE_API_KEY": f"AIzaCanary{''.join(_rand(35))}",

        # AWS-style
        "AWS_ACCESS_KEY_ID": f"AKIACANARY{''.join(_rand(16, string.ascii_uppercase + string.digits))}",
        "AWS_SECRET_ACCESS_KEY": f"{''.join(_rand(40, string.ascii_letters + string.digits + '/+'))}",

        # GitHub PAT format
        "GITHUB_TOKEN": f"ghp_canary{''.join(_rand(36))}",
    }

    for key, value in creds.items():
        _CANARY_REGISTRY[value] = key

    return creds


def is_canary_value(text: str) -> bool:
    """
    Return True if `text` contains any registered canary credential value.
    Call this on sandbox stdout/stderr to detect exfiltration attempts.
    """
    return any(canary in text for canary in _CANARY_REGISTRY)


def get_triggered_canaries(text: str) -> Dict[str, str]:
    """
    Return {canary_value: key_name} for every canary found in `text`.
    Empty dict if clean.
    """
    return {
        canary: key_name
        for canary, key_name in _CANARY_REGISTRY.items()
        if canary in text
    }


def clear_registry() -> None:
    """Clear all registered canaries (call between sessions if desired)."""
    _CANARY_REGISTRY.clear()
