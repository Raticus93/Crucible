"""
Crucible FastAPI service.

Endpoints:
  POST /exec    — main code execution endpoint (all three modes)
  GET  /health  — liveness check
  GET  /models  — list configured escalation tiers

Request body: ExecRequest
Response:     ExecResponse

apply_to_host is ALWAYS false in the response. The caller decides
whether to write code to the host filesystem.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# ─── Config loading ───────────────────────────────────────────────────────────

_CONFIG_PATH = os.getenv("CRUCIBLE_CONFIG_PATH", "./crucible_config.json")

def _load_config() -> Dict[str, Any]:
    path = Path(_CONFIG_PATH)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    raise RuntimeError(f"crucible_config.json not found at {_CONFIG_PATH}")


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class ExecRequest(BaseModel):
    task: str = Field(..., description="Natural language description of what the code should do")
    mode: str = Field(
        default="development",
        description="Execution mode: 'standard' | 'development' | 'deceptive'",
    )
    code: Optional[str] = Field(
        default=None,
        description="For 'standard' mode: pre-written code to run directly (no generation)",
    )
    artifacts: Optional[Dict[str, str]] = Field(
        default=None,
        description="Extra files to place in /workspace alongside solution.py",
    )
    # Credentials are a structured field — they are NEVER passed to LLMs
    # They are injected only as Docker env vars during execution
    credentials: Optional[Dict[str, str]] = Field(
        default=None,
        description="Real credentials to inject as Docker env vars (NEVER passed to models)",
    )
    tier_override: Optional[int] = Field(
        default=None,
        description="Force a specific escalation tier (1-indexed). Skips lower tiers.",
    )


class ThreatReport(BaseModel):
    threat_detected: bool
    threats: List[Dict[str, Any]] = []
    risk_level: str = "clean"


class EscalationEntry(BaseModel):
    tier: str
    attempt: int
    error: str
    escalated: bool


class ExecResponse(BaseModel):
    success: bool
    code: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    tier_used: str = ""
    total_attempts: int = 0
    escalation_log: List[EscalationEntry] = []
    threat_report: ThreatReport = Field(default_factory=lambda: ThreatReport(threat_detected=False))
    apply_to_host: bool = False   # ALWAYS false — caller decides
    mode: str = "development"


# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Crucible",
    description="Secure AI code generation and execution service for OpenClaw",
    version="1.0.0",
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "crucible"}


@app.get("/models")
def list_models():
    cfg = _load_config()
    return {
        "escalation_chain": [
            {
                "tier": t["tier"],
                "name": t.get("name"),
                "provider": t["provider"],
                "model": t["model"],
                "max_attempts": t.get("max_attempts", 3),
            }
            for t in cfg.get("escalation_chain", [])
        ]
    }


@app.post("/exec", response_model=ExecResponse)
def execute(req: ExecRequest):
    cfg = _load_config()
    mode = req.mode.lower()

    if mode not in ("standard", "development", "deceptive"):
        raise HTTPException(status_code=400, detail=f"Unknown mode: {mode!r}")

    threat_report = ThreatReport(threat_detected=False)

    # ── Standard mode: run pre-written code directly ─────────────────────────
    if mode == "standard":
        if not req.code:
            raise HTTPException(
                status_code=400,
                detail="'code' field is required for standard mode",
            )
        from executor.sandbox import run_in_sandbox
        result = run_in_sandbox(
            code=req.code,
            artifacts=req.artifacts,
            env_vars=req.credentials or {},
            image=cfg["sandbox"].get("image", "crucible-sandbox:latest"),
            fallback_image=cfg["sandbox"].get("fallback_image", "python:3.11-slim"),
            timeout=cfg["sandbox"].get("timeout_seconds", 30),
            memory_limit=cfg["sandbox"].get("memory_limit", "256m"),
            cpu_quota=cfg["sandbox"].get("cpu_quota", 50_000),
        )
        return ExecResponse(
            success=result["success"],
            code=req.code,
            stdout=result["stdout"],
            stderr=result["stderr"],
            exit_code=result["exit_code"],
            tier_used="standard_direct",
            total_attempts=1,
            threat_report=threat_report,
            mode="standard",
        )

    # ── Deceptive mode: multi-run honeypot with varied time/env contexts ──────
    if mode == "deceptive":
        from executor.deceptive_runner import run_deceptive
        from executor.escalation import run_development
        from security.threat_classifier import scan_code

        # Generate code first using the normal escalation chain
        # (canary creds are NOT used during generation — only during execution)
        chain = _apply_tier_override(cfg["escalation_chain"], req.tier_override)
        gen_result = run_development(
            task=req.task,
            sandbox_cfg=cfg["sandbox"],
            escalation_chain=chain,
            artifacts=req.artifacts,
            env_vars={},   # no real creds during generation
            lessons_per_prompt=cfg.get("memory", {}).get("lessons_per_prompt", 5),
        )

        # Pre-execution code scan on generated code
        code = gen_result.get("code", req.code or "")
        if code:
            code_scan = scan_code(code)
            threat_report = ThreatReport(**code_scan)

        # Run the code 3x in honeypot mode
        deceptive_result = run_deceptive(
            code=code,
            sandbox_cfg=cfg["sandbox"],
            artifacts=req.artifacts,
        )

        # Merge pre-execution code scan threats with multi-run honeypot threats
        merged = deceptive_result["merged_threat_report"]
        all_threats = threat_report.threats + merged["threats"]
        final_threat = ThreatReport(
            threat_detected=bool(all_threats or deceptive_result["canary_hits"]),
            threats=all_threats,
            risk_level=merged.get("risk_level", "clean") if not threat_report.threat_detected
                       else max(merged.get("risk_level", "clean"), threat_report.risk_level,
                                key=lambda s: {"clean":0,"low":1,"medium":2,"high":3,"critical":4}.get(s,0)),
        )

        return ExecResponse(
            success=deceptive_result["success"],
            code=code,
            stdout=deceptive_result["stdout"],
            stderr=deceptive_result["stderr"],
            exit_code=deceptive_result["exit_code"],
            tier_used=gen_result.get("tier_used", ""),
            total_attempts=gen_result.get("total_attempts", 0),
            escalation_log=[EscalationEntry(**e) for e in gen_result.get("escalation_log", [])],
            threat_report=final_threat,
            apply_to_host=False,
            mode=mode,
        )

    # ── Development mode (default): generate → sandbox → escalate ────────────
    from security.threat_classifier import scan_code
    chain = _apply_tier_override(cfg["escalation_chain"], req.tier_override)

    result = _run_development(
        req.task, cfg, chain,
        req.artifacts,
        req.credentials or {},
    )

    # Scan final code for threats before returning
    if result.get("code"):
        code_scan = scan_code(result["code"])
        threat_report = ThreatReport(**code_scan)

    return _build_response(result, threat_report, mode)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run_development(
    task: str,
    cfg: Dict[str, Any],
    chain: List[Dict[str, Any]],
    artifacts: Optional[Dict[str, str]],
    env_vars: Dict[str, str],
) -> Dict[str, Any]:
    from executor.escalation import run_development
    return run_development(
        task=task,
        sandbox_cfg=cfg["sandbox"],
        escalation_chain=chain,
        artifacts=artifacts,
        env_vars=env_vars,
        lessons_per_prompt=cfg.get("memory", {}).get("lessons_per_prompt", 5),
    )


def _apply_tier_override(
    chain: List[Dict[str, Any]],
    tier_override: Optional[int],
) -> List[Dict[str, Any]]:
    if tier_override is None:
        return chain
    # Filter to tiers >= tier_override
    filtered = [t for t in chain if t["tier"] >= tier_override]
    return filtered if filtered else chain


def _build_response(
    result: Dict[str, Any],
    threat_report: ThreatReport,
    mode: str,
) -> ExecResponse:
    return ExecResponse(
        success=result["success"],
        code=result.get("code", ""),
        stdout=result.get("stdout", ""),
        stderr=result.get("stderr", ""),
        exit_code=result.get("exit_code", -1),
        tier_used=result.get("tier_used", ""),
        total_attempts=result.get("total_attempts", 0),
        escalation_log=[EscalationEntry(**e) for e in result.get("escalation_log", [])],
        threat_report=threat_report,
        apply_to_host=False,
        mode=mode,
    )
