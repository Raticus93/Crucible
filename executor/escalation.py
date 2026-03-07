"""
Crucible escalation engine — Development mode.

Drives the full generate → sandbox → feedback → escalate loop.

Algorithm per tier:
  1. Inject ChromaDB lessons + task description + previous error feedback
  2. Call model → extract code block
  3. Run in sandbox
  4. On success → return result
  5. On failure:
     a. Classify error
     b. If same error class as previous attempt AND break_on_repeat_error → advance tier
     c. If attempts exhausted for this tier → advance tier
     d. Else → retry same tier with error feedback
  6. If all tiers exhausted → return best attempt with failure report
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from executor.error_classifier import (
    classify_error,
    format_feedback,
    is_environment_error,
)
from executor.sandbox import extract_code_block, run_in_sandbox
from memory.chroma_store import retrieve_lessons, save_lesson
from models.registry import get_model


# ─── System prompt injected into every code generation call ──────────────────

_CODEGEN_SYSTEM = """\
You are Crucible, a precise code generation engine. Your job is to write \
correct, self-contained Python code that solves the task exactly as described.

Rules:
- Output ONLY a single ```python ... ``` fenced code block. No prose before or after.
- The file is executed as /workspace/solution.py — make it self-contained.
- Do not use relative imports. Do not reference external files unless they are \
  listed in the available artifacts.
- If the task requires a package, import it; assume common packages are available \
  (requests, numpy, pandas, cryptography, etc.).
- Never print explanations. Only print task output.
"""


def run_development(
    task: str,
    sandbox_cfg: Dict[str, Any],
    escalation_chain: List[Dict[str, Any]],
    artifacts: Optional[Dict[str, str]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    lessons_per_prompt: int = 5,
) -> Dict[str, Any]:
    """
    Run the full development-mode escalation loop.

    Returns:
        {
          success: bool,
          code: str,               # final code produced
          stdout: str,
          stderr: str,
          exit_code: int,
          tier_used: str,
          total_attempts: int,
          escalation_log: list,    # per-attempt records
        }
    """
    lessons = retrieve_lessons(task, n_results=lessons_per_prompt)

    escalation_log: List[Dict[str, Any]] = []
    total_attempts = 0
    last_error_class: Optional[str] = None
    last_code = ""
    last_sandbox_result: Dict[str, Any] = {}

    for tier_cfg in escalation_chain:
        tier_name = tier_cfg.get("name", f"tier-{tier_cfg['tier']}")
        max_attempts = tier_cfg.get("max_attempts", 3)
        break_on_repeat = tier_cfg.get("break_on_repeat_error", True)
        model = get_model(tier_cfg)

        feedback_block = ""
        tier_error_class: Optional[str] = None

        for attempt in range(1, max_attempts + 1):
            total_attempts += 1
            prompt = _build_prompt(task, lessons, feedback_block)

            # Generate
            code = _generate_code(model, prompt)
            if not code:
                # Model returned nothing — escalate immediately
                escalation_log.append({
                    "tier": tier_name,
                    "attempt": attempt,
                    "error": "EmptyOutput",
                    "escalated": True,
                })
                break

            last_code = code

            # Execute
            sandbox_result = run_in_sandbox(
                code=code,
                artifacts=artifacts,
                env_vars=env_vars,
                image=sandbox_cfg.get("image", "crucible-sandbox:latest"),
                fallback_image=sandbox_cfg.get("fallback_image", "python:3.11-slim"),
                timeout=sandbox_cfg.get("timeout_seconds", 30),
                setup_timeout=sandbox_cfg.get("setup_timeout_seconds", 60),
                memory_limit=sandbox_cfg.get("memory_limit", "256m"),
                cpu_quota=sandbox_cfg.get("cpu_quota", 50_000),
            )
            last_sandbox_result = sandbox_result

            if sandbox_result["success"]:
                _maybe_save_lesson(task, tier_name, total_attempts, lessons)
                return {
                    "success": True,
                    "code": code,
                    **sandbox_result,
                    "tier_used": tier_name,
                    "total_attempts": total_attempts,
                    "escalation_log": escalation_log,
                }

            # Classify error
            error_class = classify_error(
                sandbox_result["stderr"], sandbox_result["stdout"]
            )
            escalation_log.append({
                "tier": tier_name,
                "attempt": attempt,
                "error": error_class,
                "escalated": False,
            })

            # Break on repeat error if configured
            if (
                break_on_repeat
                and tier_error_class is not None
                and error_class == tier_error_class
            ):
                escalation_log[-1]["escalated"] = True
                break

            tier_error_class = error_class
            last_error_class = error_class

            # Build feedback for next attempt
            feedback_block = format_feedback(
                attempt=total_attempts,
                tier_name=tier_name,
                error_class=error_class,
                stderr=sandbox_result["stderr"],
                stdout=sandbox_result["stdout"],
            )

            # If environment error, save to memory and break tier
            if is_environment_error(error_class):
                pkg = _extract_missing_package(sandbox_result["stderr"])
                if pkg:
                    save_lesson(
                        f"Package '{pkg}' is not available in the sandbox by default. "
                        "Either include a pip install step or use stdlib alternatives.",
                        metadata={"collection": "environment_constraints", "package": pkg},
                    )
                escalation_log[-1]["escalated"] = True
                break

    # All tiers exhausted
    return {
        "success": False,
        "code": last_code,
        **last_sandbox_result,
        "tier_used": escalation_chain[-1].get("name", "unknown") if escalation_chain else "none",
        "total_attempts": total_attempts,
        "escalation_log": escalation_log,
    }


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _build_prompt(task: str, lessons: List[str], feedback: str) -> str:
    parts = []
    if lessons:
        parts.append("=== LESSONS FROM MEMORY (follow these) ===")
        for i, lesson in enumerate(lessons, 1):
            parts.append(f"{i}. {lesson}")
        parts.append("")
    parts.append(f"=== TASK ===\n{task}")
    if feedback:
        parts.append(f"\n{feedback}")
    return "\n".join(parts)


def _generate_code(model, prompt: str) -> Optional[str]:
    from langchain_core.messages import HumanMessage, SystemMessage
    try:
        response = model.invoke([
            SystemMessage(content=_CODEGEN_SYSTEM),
            HumanMessage(content=prompt),
        ])
        return extract_code_block(response.content or "")
    except Exception:
        return None


def _extract_missing_package(stderr: str) -> Optional[str]:
    match = re.search(r"No module named '([^']+)'", stderr)
    return match.group(1).split(".")[0] if match else None


def _maybe_save_lesson(task: str, tier_name: str, attempts: int, existing_lessons: List[str]) -> None:
    """Save a lesson if we needed more than one attempt."""
    if attempts > 1:
        lesson = (
            f"Task type '{task[:80]}' required {attempts} attempts before succeeding "
            f"(solved at tier: {tier_name})."
        )
        save_lesson(lesson, metadata={"collection": "error_fix_patterns"})
