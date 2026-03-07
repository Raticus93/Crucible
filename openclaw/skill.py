"""
Crucible OpenClaw skill wrapper.

This module exposes Crucible as an OpenClaw-compatible skill.
OpenClaw calls `execute_skill(params)` and receives a structured response.

Skill contract:
  Input:  dict matching ExecRequest schema
  Output: dict matching ExecResponse schema + "apply_to_host" always False

For direct HTTP use (e.g. from OpenClaw's tool calling):
  POST http://localhost:8420/exec
  Content-Type: application/json
  Body: ExecRequest JSON

This file also provides a lightweight in-process client that avoids HTTP
overhead when Crucible and OpenClaw run in the same Python process.
"""

from typing import Any, Dict, Optional


# ─── In-process client (no HTTP) ─────────────────────────────────────────────

def execute_skill(
    task: str,
    mode: str = "development",
    code: Optional[str] = None,
    artifacts: Optional[Dict[str, str]] = None,
    credentials: Optional[Dict[str, str]] = None,
    tier_override: Optional[int] = None,
    config_path: str = "./crucible_config.json",
) -> Dict[str, Any]:
    """
    Execute a Crucible task in-process (no HTTP server required).

    This is the recommended integration point when embedding Crucible
    directly into an OpenClaw plugin or similar Python application.

    Returns the same dict schema as the /exec HTTP endpoint.
    """
    import json
    import os
    from pathlib import Path

    from dotenv import load_dotenv
    load_dotenv()

    cfg_path = Path(os.getenv("CRUCIBLE_CONFIG_PATH", config_path))
    if not cfg_path.exists():
        return {
            "success": False,
            "code": "",
            "stdout": "",
            "stderr": f"crucible_config.json not found at {cfg_path}",
            "exit_code": -1,
            "tier_used": "",
            "total_attempts": 0,
            "escalation_log": [],
            "threat_report": {"threat_detected": False, "threats": [], "risk_level": "clean"},
            "apply_to_host": False,
            "mode": mode,
        }

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    mode = mode.lower()

    # ── Standard mode ────────────────────────────────────────────────────────
    if mode == "standard":
        if not code:
            return _error_response("'code' is required for standard mode", mode)
        from executor.sandbox import run_in_sandbox
        result = run_in_sandbox(
            code=code,
            artifacts=artifacts,
            env_vars=credentials or {},
            image=cfg["sandbox"].get("image", "crucible-sandbox:latest"),
            fallback_image=cfg["sandbox"].get("fallback_image", "python:3.11-slim"),
            timeout=cfg["sandbox"].get("timeout_seconds", 30),
            memory_limit=cfg["sandbox"].get("memory_limit", "256m"),
        )
        return {**result, "code": code, "tier_used": "standard_direct",
                "total_attempts": 1, "escalation_log": [],
                "threat_report": {"threat_detected": False, "threats": [], "risk_level": "clean"},
                "apply_to_host": False, "mode": mode}

    # ── Deceptive mode ───────────────────────────────────────────────────────
    if mode == "deceptive":
        from security.canary import generate_canary_credentials
        from security.deceptive_fs import build_deceptive_artifacts
        from security.threat_classifier import scan_output
        from executor.escalation import run_development

        deceptive_artifacts = build_deceptive_artifacts(artifacts or {})
        canary_creds = generate_canary_credentials()
        chain = _apply_tier_override(cfg["escalation_chain"], tier_override)
        result = run_development(
            task=task,
            sandbox_cfg=cfg["sandbox"],
            escalation_chain=chain,
            artifacts=deceptive_artifacts,
            env_vars=canary_creds,
            lessons_per_prompt=cfg.get("memory", {}).get("lessons_per_prompt", 5),
        )
        output_scan = scan_output(result.get("stdout", ""), result.get("stderr", ""))
        return {**result, "threat_report": output_scan, "apply_to_host": False, "mode": mode}

    # ── Development mode (default) ───────────────────────────────────────────
    from executor.escalation import run_development
    from security.threat_classifier import scan_code

    chain = _apply_tier_override(cfg["escalation_chain"], tier_override)
    result = run_development(
        task=task,
        sandbox_cfg=cfg["sandbox"],
        escalation_chain=chain,
        artifacts=artifacts,
        env_vars=credentials or {},
        lessons_per_prompt=cfg.get("memory", {}).get("lessons_per_prompt", 5),
    )
    threat_report = {"threat_detected": False, "threats": [], "risk_level": "clean"}
    if result.get("code"):
        threat_report = scan_code(result["code"])

    return {**result, "threat_report": threat_report, "apply_to_host": False, "mode": mode}


# ─── HTTP client helper ───────────────────────────────────────────────────────

def execute_via_http(
    task: str,
    host: str = "http://localhost:8420",
    **kwargs,
) -> Dict[str, Any]:
    """
    Call Crucible via the HTTP API. Use this when Crucible runs as a separate service.
    """
    try:
        import httpx
    except ImportError:
        return _error_response("httpx not installed. Run: pip install httpx", "development")

    payload = {"task": task, **kwargs}
    try:
        response = httpx.post(f"{host}/exec", json=payload, timeout=120)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        return _error_response(str(exc), kwargs.get("mode", "development"))


# ─── OpenClaw skill manifest ─────────────────────────────────────────────────

SKILL_MANIFEST = {
    "name": "crucible",
    "version": "1.0.0",
    "description": (
        "Secure AI code generation and sandboxed execution. "
        "Generates Python code from a task description, runs it in an isolated "
        "Docker container, and returns verified output. Supports multi-tier model "
        "escalation and honeypot/deceptive execution for untrusted code."
    ),
    "entry_point": "openclaw.skill.execute_skill",
    "http_endpoint": "POST /exec",
    "modes": ["standard", "development", "deceptive"],
    "apply_to_host": False,
}


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _apply_tier_override(chain, tier_override):
    if tier_override is None:
        return chain
    filtered = [t for t in chain if t["tier"] >= tier_override]
    return filtered if filtered else chain


def _error_response(msg: str, mode: str) -> Dict[str, Any]:
    return {
        "success": False,
        "code": "",
        "stdout": "",
        "stderr": msg,
        "exit_code": -1,
        "tier_used": "",
        "total_attempts": 0,
        "escalation_log": [],
        "threat_report": {"threat_detected": False, "threats": [], "risk_level": "clean"},
        "apply_to_host": False,
        "mode": mode,
    }
