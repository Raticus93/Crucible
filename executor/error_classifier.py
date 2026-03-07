"""
Crucible error classifier.

Extracts a normalised error class from sandbox stderr/stdout so that the
escalation engine can detect repeat errors and advance tiers immediately.

Error classes are coarse-grained strings like "ImportError", "SyntaxError",
"AttributeError", "TimeoutError", "MemoryError", "UnknownError", etc.

The `truncate_traceback` helper keeps only the most actionable lines before
injecting into the next model prompt, saving tokens.
"""

import re
from typing import Optional


# Patterns ordered from most specific to most general
_ERROR_PATTERNS = [
    (r"\bModuleNotFoundError\b",  "ImportError"),
    (r"\bImportError\b",          "ImportError"),
    (r"\bSyntaxError\b",          "SyntaxError"),
    (r"\bIndentationError\b",     "SyntaxError"),
    (r"\bNameError\b",            "NameError"),
    (r"\bAttributeError\b",       "AttributeError"),
    (r"\bTypeError\b",            "TypeError"),
    (r"\bValueError\b",           "ValueError"),
    (r"\bKeyError\b",             "KeyError"),
    (r"\bIndexError\b",           "IndexError"),
    (r"\bZeroDivisionError\b",    "ZeroDivisionError"),
    (r"\bFileNotFoundError\b",    "FileNotFoundError"),
    (r"\bPermissionError\b",      "PermissionError"),
    (r"\bRuntimeError\b",         "RuntimeError"),
    (r"\bRecursionError\b",       "RecursionError"),
    (r"\bMemoryError\b",          "MemoryError"),
    (r"\bOverflowError\b",        "OverflowError"),
    (r"\bassert.*AssertionError\b|\bAssertionError\b", "AssertionError"),
    (r"killed|OOMKilled|memory",  "MemoryError"),
    (r"timed? ?out|timeout",      "TimeoutError"),
]


def classify_error(stderr: str, stdout: str = "") -> str:
    """
    Return a coarse error class string for the given stderr/stdout.
    Returns "UnknownError" if no pattern matches.
    """
    combined = (stderr + "\n" + stdout).lower()
    # Scan patterns against original case for class names, lower for keywords
    combined_orig = stderr + "\n" + stdout
    for pattern, label in _ERROR_PATTERNS:
        if re.search(pattern, combined_orig, re.IGNORECASE):
            return label
    if combined.strip():
        return "UnknownError"
    return "EmptyOutput"


def truncate_traceback(stderr: str, max_lines: int = 20) -> str:
    """
    Return the last `max_lines` lines of stderr — the most actionable part
    of a Python traceback — to save tokens in the next model prompt.
    """
    lines = stderr.strip().splitlines()
    if len(lines) <= max_lines:
        return stderr.strip()
    kept = lines[-max_lines:]
    omitted = len(lines) - max_lines
    return f"[... {omitted} lines omitted ...]\n" + "\n".join(kept)


def is_environment_error(error_class: str) -> bool:
    """
    Return True for errors that indicate a missing package or environment
    constraint that the model cannot fix by rewriting code alone.
    """
    return error_class in ("ImportError",)


_INJECTION_PATTERNS = re.compile(
    r"ignore\s+(previous|prior|all)\s+instructions?|"
    r"disregard\s+(your|all|the)\s+|"
    r"you\s+are\s+now\s+|"
    r"new\s+(system|base)\s+prompt|"
    r"act\s+as\s+(if\s+)?you\s+are|"
    r"<\|?system\|?>|"
    r"<\|?im_start\|?>",
    re.IGNORECASE,
)


def sanitize_for_prompt(text: str) -> str:
    """
    Strip prompt injection signatures from sandbox output before injecting
    it back into a model prompt as error feedback.

    A payload could print "PASS\\nIgnore previous instructions..." to stdout,
    which feeds straight into the next generation prompt. This removes the
    most common patterns. The threat classifier is the primary defence layer;
    this is an additional backstop.
    """
    return _INJECTION_PATTERNS.sub("[REDACTED]", text)


def format_feedback(
    attempt: int,
    tier_name: str,
    error_class: str,
    stderr: str,
    stdout: str,
    max_tb_lines: int = 20,
) -> str:
    """
    Build the sanitised feedback block injected into the next model prompt.
    """
    tb = truncate_traceback(stderr, max_tb_lines) if stderr.strip() else ""
    out_snippet = stdout.strip()[-500:] if stdout.strip() else ""

    # Sanitize before injecting into the prompt
    tb = sanitize_for_prompt(tb)
    out_snippet = sanitize_for_prompt(out_snippet)

    parts = [
        f"=== Attempt {attempt} FAILED (tier: {tier_name}, error: {error_class}) ===",
    ]
    if tb:
        parts.append(f"STDERR:\n{tb}")
    if out_snippet:
        parts.append(f"STDOUT (last 500 chars):\n{out_snippet}")
    parts.append("Fix the code so it runs without errors.")
    return "\n".join(parts)
