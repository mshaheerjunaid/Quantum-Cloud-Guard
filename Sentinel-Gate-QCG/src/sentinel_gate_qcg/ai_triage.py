"""AI-assisted incident triage (OUT OF BAND).

This is the only place a large language model is used, and it runs *off* the
request path -- as an on-demand analyst tool, never as a per-request
dependency. It reads the structured access log, computes deterministic
aggregate statistics locally (top talkers, error-heavy identities, decision
mix, robotic-timing suspects), and -- if an Anthropic API key is configured --
asks Claude to summarise the incident, extract indicators of compromise, and
suggest mitigations.

Run it after an incident:

    python -m sentinel_gate_qcg.ai_triage access_logs.jsonl

The deterministic summary always prints. The LLM section is additive and is
skipped cleanly when no API key is present, so triage never depends on a
remote service being reachable.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from typing import Any


def load_events(path: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def summarise(events: list[dict[str, Any]]) -> dict[str, Any]:
    decisions = collections.Counter(e.get("decision", "?") for e in events)
    by_ip = collections.Counter(e.get("ip", "?") for e in events)
    errors = collections.Counter(
        e.get("ip", "?") for e in events if int(e.get("status", 0)) >= 400
    )
    high_anomaly = collections.Counter(
        e.get("ip", "?") for e in events if float(e.get("anomaly", 0)) >= 0.6
    )
    endpoints = collections.Counter(e.get("endpoint", "?") for e in events)
    return {
        "total_events": len(events),
        "decision_mix": dict(decisions),
        "top_talkers": by_ip.most_common(10),
        "top_error_sources": errors.most_common(10),
        "high_anomaly_sources": high_anomaly.most_common(10),
        "top_endpoints": endpoints.most_common(10),
    }


def render_text(summary: dict[str, Any]) -> str:
    lines = [
        "=== Sentinel Gate QCG Deterministic Triage ===",
        f"Total events: {summary['total_events']}",
        f"Decision mix: {summary['decision_mix']}",
        "Top talkers:",
        *[f"  {ip}: {n}" for ip, n in summary["top_talkers"]],
        "Top error sources:",
        *[f"  {ip}: {n}" for ip, n in summary["top_error_sources"]],
        "High-anomaly sources:",
        *[f"  {ip}: {n}" for ip, n in summary["high_anomaly_sources"]],
        "Top endpoints:",
        *[f"  {ep}: {n}" for ep, n in summary["top_endpoints"]],
    ]
    return "\n".join(lines)


def llm_triage(summary: dict[str, Any]) -> str | None:
    """Optional. Returns Claude's analysis, or None if unavailable."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic  # optional dependency
    except ImportError:
        return None

    client = anthropic.Anthropic(api_key=api_key)
    prompt = (
        "You are a SOC analyst. Given these aggregate statistics from a DDoS "
        "mitigation gateway's access log, write a concise incident assessment: "
        "(1) is this consistent with an L7 DDoS or scanning campaign, (2) the "
        "indicators of compromise to block, and (3) concrete mitigation steps. "
        "Be specific and do not invent data beyond what is provided.\n\n"
        f"{json.dumps(summary, indent=2)}"
    )
    try:
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in msg.content if block.type == "text")
    except Exception as exc:  # pragma: no cover - network/credentials
        return f"[LLM triage unavailable: {exc}]"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Gate QCG AI log triage")
    parser.add_argument("logfile", help="Path to access log (JSON lines)")
    args = parser.parse_args(argv)

    events = load_events(args.logfile)
    summary = summarise(events)
    print(render_text(summary))

    analysis = llm_triage(summary)
    if analysis:
        print("\n=== Claude Incident Assessment ===")
        print(analysis)
    else:
        print("\n[LLM triage skipped: set ANTHROPIC_API_KEY and "
              "`pip install anthropic` to enable.]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
