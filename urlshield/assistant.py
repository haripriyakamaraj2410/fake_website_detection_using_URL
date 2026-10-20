"""Optional Claude assistant that receives only opt-in URL scan summaries."""

from __future__ import annotations

import json
import os
import re
from urllib.request import Request, urlopen


def ask_claude(question: str, summary: dict, language: str = "English") -> str:
    """Send the explicitly approved, minimized scan summary to the Claude API."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not configured.")
    safe_context = {
        "verdict": summary["verdict"],
        "risk_score": summary["risk_score"],
        "probabilities": summary["probabilities"],
        "red_flags": summary["red_flags"],
        "green_flags": summary["green_flags"],
    }
    # Redact URL-like text in the question so the scanned destination is not sent.
    safe_question = re.sub(
        r"(?i)\b(?:https?://|www\.)[^\s<>\"']+",
        "[URL omitted]",
        question[:1000],
    )
    safe_question = re.sub(
        r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s<>\"']*)?",
        "[URL omitted]",
        safe_question,
    )
    safe_question = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>\"']*)?", "[URL omitted]", safe_question)
    payload = {
        "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
        "max_tokens": 400,
        "system": f"Explain this URL scan in simple {language}. This is a URL-pattern prediction, not certainty. Do not claim the site was opened or verified.",
        "messages": [{"role": "user", "content": "Scan summary (no webpage content): "
                      + json.dumps(safe_context, ensure_ascii=True)
                      + "\nQuestion: " + safe_question}],
    }
    request = Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
        return "\n".join(block.get("text", "") for block in data.get("content", []))
    except Exception as exc:
        raise RuntimeError(f"Claude request failed: {exc}") from exc
