"""Generate local HTML and PDF scan reports."""

from __future__ import annotations

from html import escape
from io import BytesIO


def report_html(result: dict) -> str:
    flags = "".join(
        f"<li><strong>{escape(flag['name'])}</strong> — {escape(flag['message'])} "
        f"<code>{escape(flag['value'])}</code></li>"
        for flag in result["signals"]["red_flags"]
    ) or "<li>No configured red flags were detected.</li>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>URL Shield report</title>
<style>body{{font:16px Arial,sans-serif;max-width:850px;margin:40px auto;color:#172033}}
.warn{{color:#a32222}}code{{background:#f0f2f7;padding:3px}}</style></head><body>
<h1>URL Shield scan report</h1><p><b>URL text:</b> <code>{escape(result['url'])}</code></p>
<h2 class="warn">{escape(result['verdict'].upper())} — risk {result['risk_score']}/100</h2>
<p>Confidence: {result['confidence']:.1%}. Source: {escape(result['source'])}</p>
<p>Prediction from URL patterns only. Not a guarantee of safety.</p><h2>Red flags</h2><ul>{flags}</ul>
</body></html>"""


def report_pdf(result: dict) -> bytes:
    """Create a compact PDF report; raises a clear error if ReportLab is absent."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError("PDF export requires reportlab. Install dependencies from requirements.txt.") from exc

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 55
    pdf.setTitle("URL Shield scan report")
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(48, y, "URL Shield scan report")
    y -= 34
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(48, y, f"{result['verdict'].upper()} — risk {result['risk_score']}/100")
    y -= 25
    pdf.setFont("Helvetica", 9)
    for line in (
        f"URL text: {result['url']}",
        f"Confidence: {result['confidence']:.1%}. Source: {result['source']}",
        "Prediction from URL patterns only. Not a guarantee of safety.",
        "",
        "Red flags:",
    ):
        for chunk_start in range(0, max(1, len(line)), 100):
            if y < 55:
                pdf.showPage()
                y = height - 55
                pdf.setFont("Helvetica", 9)
            pdf.drawString(48, y, line[chunk_start:chunk_start + 100])
            y -= 15
    for flag in result["signals"]["red_flags"] or [{"message": "No configured red flags were detected.", "value": ""}]:
        text = f"- {flag['message']} Value: {flag['value']}"
        for chunk_start in range(0, len(text), 100):
            if y < 55:
                pdf.showPage()
                y = height - 55
                pdf.setFont("Helvetica", 9)
            pdf.drawString(58, y, text[chunk_start:chunk_start + 100])
            y -= 15
    pdf.save()
    return buffer.getvalue()
