"""
Crucible deceptive execution runner.

Architecture: two containers, one internal Docker network.

  ┌─────────────────────────────┐     internal Docker network
  │   solution container        │◄───────────────────────────► [no internet]
  │   runs solution.py          │         │
  │   env vars point to fake LLM│         │ HTTP 8080
  │   audit hook active         │         ▼
  └─────────────────────────────┘   ┌─────────────────┐
                                     │ fake LLM        │
                                     │ python:3.11-slim│
                                     │ logs requests   │
                                     │ to stdout       │
                                     └─────────────────┘

An internal=True Docker network allows container-to-container communication
but has zero external internet access — no NAT, no default gateway.

The malicious code finds a convincing LLM API at the env-var address, attacks
it (revealing its full intent), and we collect everything the fake LLM saw.

Three run contexts vary the clock and OS fingerprint to maximise coverage of
time-conditional and environment-conditional payloads.
"""

import time
import uuid
from typing import Any, Dict, List, Optional

import docker

from executor.sandbox import _FAKE_LLM_SERVER_PY, _build_tar, _cleanup, run_in_sandbox
from security.canary import generate_canary_credentials, get_triggered_canaries
from security.deceptive_fs import build_deceptive_artifacts, rich_os_env_vars
from security.threat_classifier import scan_audit_log, scan_llm_log, scan_output


# Three run contexts: (label, faketime_offset, hostname, username)
_RUN_CONTEXTS = [
    ("baseline",    None,         "dev-workstation-01", "developer"),
    ("future-35d",  "+35d",       "MacBook-Pro-M3",     "jackf"),
    ("accel-clock", "+0 x3600",   "ubuntu-22-desktop",  "ubuntu"),
]


def run_deceptive(
    code: str,
    sandbox_cfg: Dict[str, Any],
    artifacts: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Execute `code` in the honeypot sandbox across 3 varied contexts.

    Each run:
      - Creates an isolated internal Docker network
      - Starts a fake LLM container (logs all agent contact attempts)
      - Runs the solution container with canary creds + rich OS env pointing at fake LLM
      - Collects stdout, audit log, and LLM intercept log
      - Tears down the network and both containers

    Returns:
        {
          success: bool,
          stdout: str,               — from baseline run
          stderr: str,               — from baseline run
          exit_code: int,
          runs: list,                — per-run detail records
          merged_threat_report: dict,
          canary_hits: list,         — [{run, key_name}]
        }
    """
    client = docker.from_env()
    run_records = []
    all_threats = []
    all_canary_hits = []
    baseline_result = None

    for label, faketime, hostname, username in _RUN_CONTEXTS:
        network = None
        llm_container = None

        try:
            # ── 1. Internal network (container-to-container only, no internet) ───
            net_name = f"crucible_deceptive_{uuid.uuid4().hex[:8]}"
            network = client.networks.create(net_name, internal=True, driver="bridge")

            # ── 2. Start fake LLM container ───────────────────────────────────
            llm_tar = _build_tar("", {"_fake_llm.py": _FAKE_LLM_SERVER_PY})
            llm_container = client.containers.create(
                "python:3.11-slim",
                command=["python", "/workspace/_fake_llm.py"],
                working_dir="/workspace",
                network=net_name,
            )
            llm_container.put_archive("/workspace", llm_tar)
            llm_container.start()

            # Give the server a moment to bind
            time.sleep(0.8)

            # Discover fake LLM IP on our internal network
            llm_container.reload()
            net_info = llm_container.attrs["NetworkSettings"]["Networks"].get(net_name, {})
            llm_ip = net_info.get("IPAddress", "127.0.0.1")

            # ── 3. Build honeypot environment ─────────────────────────────────
            canary_creds = generate_canary_credentials()
            os_env = rich_os_env_vars(hostname=hostname, username=username)
            env_vars = {
                **canary_creds,
                **os_env,
                # Point all LLM SDK env vars at our fake server
                "ANTHROPIC_BASE_URL":  f"http://{llm_ip}:8080",
                "OPENAI_BASE_URL":     f"http://{llm_ip}:8080/v1",
                "OPENAI_API_BASE":     f"http://{llm_ip}:8080/v1",
                "OLLAMA_HOST":         f"http://{llm_ip}:8080",
                "OLLAMA_BASE_URL":     f"http://{llm_ip}:8080",
            }

            deceptive_artifacts = build_deceptive_artifacts(artifacts or {})

            # ── 4. Run solution container on the same internal network ─────────
            result = run_in_sandbox(
                code=code,
                artifacts=deceptive_artifacts,
                env_vars=env_vars,
                image=sandbox_cfg.get("image", "crucible-sandbox:latest"),
                fallback_image=sandbox_cfg.get("fallback_image", "python:3.11-slim"),
                timeout=sandbox_cfg.get("timeout_seconds", 30),
                memory_limit=sandbox_cfg.get("memory_limit", "256m"),
                cpu_quota=sandbox_cfg.get("cpu_quota", 50_000),
                faketime_offset=faketime,
                collect_audit_log=True,
                network_name=net_name,
            )

            # ── 5. Retrieve LLM intercept log from fake LLM stdout ────────────
            llm_log = _parse_llm_stdout(llm_container)

        finally:
            _cleanup(llm_container)
            if network:
                try:
                    network.remove()
                except Exception:
                    pass

        # ── Scan this run ─────────────────────────────────────────────────────
        output_scan = scan_output(result["stdout"], result["stderr"])
        audit_scan  = scan_audit_log(result["audit_log"])
        llm_scan    = scan_llm_log(llm_log)

        combined_output = result["stdout"] + result["stderr"]
        triggered = get_triggered_canaries(combined_output)
        # Also check LLM request bodies for canary hits
        for entry in llm_log:
            triggered.update(get_triggered_canaries(entry.get("body", "") + entry.get("auth", "")))

        for value, key_name in triggered.items():
            all_canary_hits.append({"run": label, "key_name": key_name})

        run_records.append({
            "label": label,
            "faketime": faketime,
            "hostname": hostname,
            "success": result["success"],
            "exit_code": result["exit_code"],
            "stdout_snippet": result["stdout"][:500],
            "stderr_snippet": result["stderr"][:500],
            "audit_events": len(result["audit_log"]),
            "llm_requests": len(llm_log),
            "output_threats": output_scan["threats"],
            "audit_threats": audit_scan["threats"],
            "llm_threats": llm_scan["threats"],
            "canary_hits": list(triggered.values()),
        })

        for scan in (output_scan, audit_scan, llm_scan):
            if scan["threats"]:
                all_threats.extend(scan["threats"])

        if label == "baseline":
            baseline_result = result

    # ── Merge and deduplicate threats ─────────────────────────────────────────
    seen = set()
    unique_threats = []
    for t in all_threats:
        key = (t["threat_type"], t.get("match", "")[:60])
        if key not in seen:
            seen.add(key)
            unique_threats.append(t)

    _sev = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if unique_threats or all_canary_hits:
        max_sev = max(
            (_sev.get(t["severity"], 0) for t in unique_threats),
            default=4 if all_canary_hits else 0,
        )
        risk_level = {v: k for k, v in _sev.items()}.get(max_sev, "high")
    else:
        risk_level = "clean"

    base = baseline_result or {}
    return {
        "success": base.get("success", False),
        "stdout": base.get("stdout", ""),
        "stderr": base.get("stderr", ""),
        "exit_code": base.get("exit_code", -1),
        "runs": run_records,
        "merged_threat_report": {
            "threat_detected": bool(unique_threats or all_canary_hits),
            "threats": unique_threats,
            "risk_level": risk_level,
        },
        "canary_hits": all_canary_hits,
    }


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _parse_llm_stdout(container) -> List[Dict[str, Any]]:
    """
    The fake LLM server prints one JSON object per request to stdout.
    Retrieve and parse them.
    """
    try:
        raw = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        entries = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    entries.append(__import__("json").loads(line))
                except Exception:
                    pass
        return entries
    except Exception:
        return []
