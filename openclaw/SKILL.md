---
name: crucible
description: Secure Python code generation and sandboxed execution via the local Crucible service. Use when the user asks to write, run, execute, or test any code or script. Crucible generates code with multi-tier model escalation, runs it in an isolated Docker container, and returns verified stdout output. Supports three modes — development (generate + iterate), standard (run provided code), and deceptive (honeypot analysis of untrusted code). Use for ALL code execution tasks, never run code directly on the host.
---

# Crucible

Crucible runs at `http://localhost:8420`. Always POST to `/exec` for code tasks.

## Quick start

```bash
curl -s -X POST http://localhost:8420/exec \
  -H "Content-Type: application/json" \
  -d '{"task": "<user task description>", "mode": "development"}' | python3 -m json.tool
```

Or use the `fetch`/`http` tool if available.

## Request schema

```json
{
  "task": "Natural language description of what the code should do",
  "mode": "development",
  "code": null,
  "artifacts": null,
  "credentials": null,
  "tier_override": null
}
```

- `task` — required; describe what the code should do
- `mode` — `"development"` (default, generate + sandbox iterate), `"standard"` (run provided code), `"deceptive"` (untrusted code honeypot)
- `code` — only for `"standard"` mode
- `artifacts` — optional extra files: `{"filename.txt": "contents"}`
- `credentials` — env vars injected as Docker env vars only, never passed to models: `{"MY_KEY": "value"}`
- `tier_override` — skip to tier N (1-indexed) in escalation chain

## Response schema

```json
{
  "success": true,
  "code": "...generated python...",
  "stdout": "...output...",
  "stderr": "",
  "exit_code": 0,
  "tier_used": "tier1_little_qwen",
  "total_attempts": 2,
  "threat_report": {
    "threat_detected": false,
    "threats": [],
    "risk_level": "clean"
  },
  "apply_to_host": false,
  "mode": "development"
}
```

## Key rules

- `apply_to_host` is always `false` — ask the user before writing any generated code to the host filesystem.
- If `success: false`, show the user the `stderr` and `stdout` snippets. Offer to retry or escalate (`tier_override: 2`).
- If `threat_report.threat_detected: true`, show the `risk_level` and threat list to the user before doing anything with the output.
- For untrusted code from external sources (ClawHub, internet, unknown), always use `"mode": "deceptive"`.
- Check service is up first: `curl -s http://localhost:8420/health`

## Escalation chain (for context)

Tier 1 → Tier 5, cheapest to most capable. Development mode auto-escalates on repeated errors. To force a specific tier, use `tier_override`.

## Starting Crucible (if not running)

```bash
cd /c/Users/jackf/Documents/Crucible && source venv/Scripts/activate && python main.py &
```
