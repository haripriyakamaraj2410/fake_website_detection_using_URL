"""URL Shield: URL-pattern malicious-link detector."""

from __future__ import annotations

import html
import os
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots
from urllib.parse import urlsplit

from urlshield.assistant import ask_claude
from urlshield.features import FEATURE_COLUMNS, feature_dict, validate_url_input
from urlshield.live_checks import run_live_checks
from urlshield.models import CLASSES, heuristic_prediction, load_models, predict_one, risk_score
from urlshield.precautions import ADVICE, RECOVERY_STEPS
from urlshield.reports import report_html, report_pdf
from urlshield.signals import analyze_signals

ROOT = Path(__file__).resolve().parent
st.set_page_config(page_title="URL Shield", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .main .block-container {max-width: 1250px; padding-top: 1.5rem}
    .verdict {padding: 1.2rem 1.4rem; border-radius: 16px; border: 1px solid #d7dce5}
    .verdict.safe {background:#eaf8ef; color:#14532d}
    .verdict.danger {background:#fff0ef; color:#7f1d1d}
    .verdict.unknown {background:#fff8e6; color:#713f12}
    .small-note {color:#64748b;font-size:.9rem}
    </style>
    """,
    unsafe_allow_html=True,
)


def _analyze_signals(url: str) -> dict:
    return analyze_signals(url)


def scan_url(url: str, models: dict, columns: list[str]) -> dict:
    """Analyze one URL locally and run every available model."""
    signals = _analyze_signals(url)
    comparisons = {}
    for label, model in models.items():
        comparisons[label] = predict_one(model, url, columns)
    if comparisons:
        primary = comparisons.get("Tree model") or comparisons.get("MLP model")
        source = "Pre-trained model: " + ("Tree model" if "Tree model" in comparisons else "MLP model")
    else:
        primary = heuristic_prediction(url, signals["red_flags"])
        source = primary["source"]
    return {
        "url": url,
        "verdict": primary["verdict"],
        "probabilities": primary["probabilities"],
        "confidence": primary["confidence"],
        "risk_score": primary.get("risk_score", risk_score(primary["probabilities"])),
        "source": source,
        "signals": signals,
        "comparisons": comparisons,
    }


def _result_frame(items: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "URL": item["url"],
                "Verdict": item["verdict"],
                "Risk score": item["risk_score"],
                "Top reason": (
                    f'{item["signals"]["red_flags"][0]["message"]} '
                    f'({item["signals"]["red_flags"][0]["value"]})'
                    if item["signals"]["red_flags"] else "No configured red flags detected"
                ),
            }
            for item in items
        ]
    )


def _probability_chart(probabilities: dict[str, float]) -> go.Figure:
    colors = ["#16a34a", "#b45309", "#dc2626", "#ea580c"]
    figure = go.Figure(
        go.Bar(
            x=[probabilities.get(label, 0) * 100 for label in CLASSES],
            y=[label.title() for label in CLASSES],
            orientation="h",
            marker_color=colors,
            text=[f"{probabilities.get(label, 0):.1%}" for label in CLASSES],
            textposition="outside",
        )
    )
    figure.update_layout(
        height=250, margin=dict(l=8, r=25, t=15, b=10),
        xaxis=dict(range=[0, 105], title="Model probability (%)"),
        yaxis=dict(autorange="reversed"), showlegend=False,
    )
    return figure


def _risk_gauge(value: int) -> go.Figure:
    figure = go.Figure(go.Indicator(
        mode="gauge+number", value=value, number={"suffix": "/100"},
        title={"text": "Risk score"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#dc2626" if value >= 50 else "#d97706" if value >= 25 else "#16a34a"},
            "steps": [
                {"range": [0, 25], "color": "#dcfce7"},
                {"range": [25, 60], "color": "#fef3c7"},
                {"range": [60, 100], "color": "#fee2e2"},
            ],
        },
    ))
    figure.update_layout(height=230, margin=dict(l=20, r=20, t=35, b=5))
    return figure


def _show_anatomy(url: str, signals: dict) -> None:
    parsed = urlsplit(url if "://" in url else f"//{url}")
    red_names = {flag["name"] for flag in signals["red_flags"]}
    protocol_bad = "no_https" in red_names
    host_bad = bool(red_names.intersection({"raw_ip", "subdomains", "rare_tld", "idn", "shortener", "brand_lookalike"}))
    path_bad = bool(red_names.intersection({"executable", "deep_path"}))
    query_bad = bool(red_names.intersection({"at_symbol", "suspicious_words", "encoded_chars"}))

    def part(title: str, value: str, bad: bool = False) -> str:
        color = "#fee2e2" if bad else "#dcfce7"
        return (
            f'<div style="padding:10px;background:{color};border-radius:8px;min-width:110px">'
            f'<small>{html.escape(title)}</small><br><code>{html.escape(value or "(empty)")}</code></div>'
        )

    st.markdown(
        '<div style="display:flex;gap:8px;flex-wrap:wrap">'
        + part("Protocol", parsed.scheme or "not specified", protocol_bad)
        + part("Subdomain", signals["subdomains"], host_bad)
        + part("Domain", signals["domain"], host_bad)
        + part("TLD", signals["tld"], "rare_tld" in red_names)
        + part("Path", signals["path"], path_bad)
        + part("Query", parsed.query, query_bad)
        + "</div>",
        unsafe_allow_html=True,
    )
    st.caption("Red = a measured URL signal was detected; green = no matching configured red flag. Anatomy is a text parse, not a site visit.")


def _feature_chart(result: dict, models: dict) -> None:
    model = models.get("Tree model") or models.get("MLP model")
    if model is None:
        st.info("Feature attribution is unavailable because no trained model is loaded.")
        return
    contributions = None
    attribution_note = ""
    try:
        import numpy as np
        import shap

        explainer = shap.TreeExplainer(model)
        values = explainer.shap_values(np.asarray([list(feature_dict(result["url"]).values())], dtype=float))
        model_classes = [str(label).lower() for label in getattr(model, "classes_", CLASSES)]
        class_index = model_classes.index(result["verdict"]) if result["verdict"] in model_classes else 0
        if isinstance(values, list):
            vector = values[class_index][0]
        else:
            array = np.asarray(values)
            if array.ndim == 3:
                vector = array[0, :, class_index]
            elif array.ndim == 2:
                vector = array[0]
            else:
                raise ValueError("Unsupported SHAP output shape.")
        contributions = sorted(zip(FEATURE_COLUMNS, vector), key=lambda item: abs(float(item[1])), reverse=True)[:8]
        attribution_note = f"SHAP contributions toward the {result['verdict']} class for this URL."
    except ImportError:
        attribution_note = "SHAP is not installed; showing global model feature importance, not per-URL contribution."
    except Exception as exc:
        attribution_note = f"Per-URL SHAP attribution could not be computed ({exc}); showing global importance if available."

    if contributions is None:
        importances = getattr(model, "feature_importances_", None)
        if importances is None:
            st.info(attribution_note + " This model does not expose feature importance.")
            return
        contributions = sorted(zip(FEATURE_COLUMNS, importances), key=lambda item: float(item[1]), reverse=True)[:8]
        chart_title = "Global feature importance"
    else:
        chart_title = "Per-URL model contribution"
    names, values = zip(*contributions)
    figure = go.Figure(go.Bar(
        x=[float(value) for value in values], y=list(names), orientation="h",
        marker_color=["#dc2626" if float(value) < 0 else "#2563eb" for value in values],
    ))
    figure.update_layout(title=chart_title, height=300, margin=dict(l=10, r=10, t=45, b=10), yaxis={"autorange": "reversed"})
    st.plotly_chart(figure, use_container_width=True)
    if contributions and "Per-URL" in chart_title:
        st.caption(attribution_note + " Blue supports the predicted class; red weighs against it.")
    else:
        st.caption(attribution_note)


def _render_scan(result: dict, models: dict, columns: list[str]) -> None:
    danger = result["verdict"] != "benign"
    state = "safe" if not danger else "danger"
    name = result["verdict"].upper()
    st.markdown(
        f'<div class="verdict {state}"><h1 style="margin:0">{name}</h1>'
        f'<b>{result["risk_score"]}/100 risk · {result["confidence"]:.1%} confidence</b>'
        f'<div>{html.escape(result["source"])}</div></div>',
        unsafe_allow_html=True,
    )
    if not models:
        st.warning(
            "Trained model artifacts were not found. This is a URL-pattern heuristic only, "
            "not a trained-model prediction. Add best_url_model.pkl, mlp_url_model.pkl, "
            "and url_feature_columns.pkl to the project folder."
        )
    left, right = st.columns([1, 1.4])
    with left:
        st.plotly_chart(_risk_gauge(result["risk_score"]), use_container_width=True)
    with right:
        st.subheader("Class probabilities")
        st.plotly_chart(_probability_chart(result["probabilities"]), use_container_width=True)

    st.subheader("Why this verdict")
    red_col, green_col = st.columns(2)
    with red_col:
        st.markdown("#### 🔴 Red flags")
        if result["signals"]["red_flags"]:
            for flag in result["signals"]["red_flags"]:
                st.markdown(f"- **{flag['name'].replace('_', ' ').title()}** — {flag['message']}  \n  Measured value: `{flag['value']}`")
        else:
            st.write("No configured red flags were detected.")
    with green_col:
        st.markdown("#### 🟢 Green flags")
        for flag in result["signals"]["green_flags"]:
            st.markdown(f"- **{flag['name'].replace('_', ' ').title()}** — {flag['message']}  \n  Measured value: `{flag['value']}`")

    st.markdown("#### Model feature signals")
    _feature_chart(result, models)

    st.subheader("URL anatomy")
    _show_anatomy(result["url"], result["signals"])

    st.subheader("Model comparison")
    if result["comparisons"]:
        agree = len({item["verdict"] for item in result["comparisons"].values()}) <= 1
        cols = st.columns(max(1, len(result["comparisons"])))
        for col, (label, prediction) in zip(cols, result["comparisons"].items()):
            col.metric(label, prediction["verdict"].upper(), f'{prediction["confidence"]:.1%} confidence')
        if not agree:
            st.warning("The loaded models disagree. Treat this result cautiously; do not rely on one prediction alone.")
        else:
            st.success("All loaded models agree.")
    else:
        st.info("No trained models are currently loaded; only the clearly labeled heuristic fallback is shown.")

    advice = ADVICE.get(result["verdict"], ADVICE["phishing"])
    st.subheader("Practical precautions")
    st.write(advice["meaning"])
    action_col, never_col = st.columns(2)
    with action_col:
        st.markdown("**What to do now**")
        for item in advice["now"]:
            st.markdown(f"- {item}")
    with never_col:
        st.markdown("**What never to do**")
        for item in advice["never"]:
            st.markdown(f"- {item}")

    with st.expander("I already clicked / entered my password"):
        for index, step in enumerate(RECOVERY_STEPS, 1):
            st.markdown(f"{index}. {step}")
    country = st.selectbox("Report it — choose your country", ["India", "United States", "United Kingdom", "Other"], key="country")
    if country == "India":
        st.info("India: National Cybercrime Reporting Portal: https://cybercrime.gov.in · Cybercrime helpline: 1930")
    elif country == "United States":
        st.info("United States: Report phishing to reportphishing@apwg.org; report cybercrime at https://www.ic3.gov/")
    elif country == "United Kingdom":
        st.info("United Kingdom: Forward suspicious texts to 7726; report fraud at https://www.actionfraud.police.uk/")
    else:
        st.info("Contact your national cybercrime reporting authority and your financial institution using independently verified contact details.")

    live_enabled = st.toggle(
        "Run optional live metadata checks (contacts this hostname)",
        value=False,
        help="This performs DNS, TLS-certificate, and HTTP HEAD checks. It does not request or render a page body; the remote server can still observe these requests.",
    )
    if live_enabled:
        st.warning("Extra signals only—not part of the model. These checks contact the hostname and may reveal your IP address. No page body is downloaded.")
        with st.spinner("Checking DNS, TLS metadata and HEAD response..."):
            try:
                checks = run_live_checks(result["url"])
                st.dataframe(pd.DataFrame(checks), hide_index=True, use_container_width=True)
            except Exception as exc:
                st.error(f"Live checks failed: {exc}")

    report_col1, report_col2 = st.columns(2)
    with report_col1:
        st.download_button(
            "Download HTML report", report_html(result),
            file_name="url-shield-report.html", mime="text/html",
        )
    with report_col2:
        try:
            pdf = report_pdf(result)
        except RuntimeError as exc:
            st.caption(str(exc))
        else:
            st.download_button("Download PDF report", pdf, file_name="url-shield-report.pdf", mime="application/pdf")

    if os.getenv("ANTHROPIC_API_KEY"):
        with st.expander("Ask about this URL (optional AI assistant)"):
            enabled = st.checkbox(
                "I explicitly consent to send only the verdict, class probabilities, and red/green flags to Claude. The URL itself and webpage content are not sent.",
                key="assistant_consent",
            )
            language = st.selectbox("Answer language", ["English", "Tamil"], key="assistant_language")
            question = st.text_input("Your question", key="assistant_question", max_chars=1000)
            if st.button("Ask", disabled=not enabled or not question):
                summary = {
                    "verdict": result["verdict"],
                    "risk_score": result["risk_score"],
                    "probabilities": result["probabilities"],
                    "red_flags": result["signals"]["red_flags"],
                    "green_flags": result["signals"]["green_flags"],
                }
                with st.spinner("Asking Claude..."):
                    try:
                        st.write(ask_claude(question, summary, language))
                    except RuntimeError as exc:
                        st.error(str(exc))


def _single_scan(models: dict, columns: list[str]) -> None:
    st.title("🛡️ URL Shield")
    st.caption("Check URL text for phishing, malware, and defacement patterns—without opening the website.")
    for col, (label, example) in zip(
        st.columns(3),
        [
            ("Example: familiar domain", "https://www.wikipedia.org/"),
            ("Example: suspicious login", "http://secure-paypal-login.example.com/account/verify"),
            ("Example: raw IP address", "http://192.0.2.10/login"),
        ],
    ):
        if col.button(label, use_container_width=True):
            st.session_state["url_input"] = example

    with st.form("scan_form"):
        url = st.text_input("Paste a URL", key="url_input", placeholder="https://example.com/account")
        submitted = st.form_submit_button("Scan URL", type="primary", use_container_width=True)
    if submitted:
        is_valid, reason = validate_url_input(url)
        if not is_valid:
            st.error(reason)
            st.session_state.pop("last_scan", None)
        else:
            with st.spinner("Analyzing URL text locally..."):
                try:
                    result = scan_url(url.strip(), models, columns)
                except Exception as exc:
                    st.error(f"Could not analyze this URL: {exc}")
                    return
            st.session_state["last_scan"] = result
            history = st.session_state.setdefault("history", [])
            history.insert(0, result)
            del history[100:]
    if st.session_state.get("last_scan"):
        _render_scan(st.session_state["last_scan"], models, columns)
    else:
        st.info("Paste a URL and select **Scan URL**. No DNS lookup or page request is made by a standard scan.")
    st.caption("Prediction from URL patterns only. Not a guarantee of safety.")


def _batch_scan(models: dict, columns: list[str]) -> None:
    st.title("Batch scan")
    st.write("Paste one URL per line, or upload a CSV with a `url` column (or URLs in the first column).")
    pasted = st.text_area("URLs", height=150, placeholder="https://example.com\nhttps://another.example")
    uploaded = st.file_uploader("Upload CSV", type=["csv"], key="batch_csv")
    submitted = st.button("Scan batch", type="primary")
    if not submitted:
        if "batch_results" in st.session_state:
            _show_batch_table(st.session_state["batch_results"])
        return
    urls = [line.strip() for line in pasted.splitlines() if line.strip()]
    if uploaded:
        try:
            frame = pd.read_csv(uploaded, dtype=str)
            column = next((name for name in frame.columns if name.strip().lower() == "url"), frame.columns[0] if len(frame.columns) else None)
            if column:
                urls.extend(frame[column].dropna().astype(str).tolist())
        except Exception as exc:
            st.error(f"Could not read the CSV: {exc}")
            return
    urls = list(dict.fromkeys(url.strip() for url in urls if url.strip()))
    if not urls:
        st.error("Enter or upload at least one URL.")
        return
    if len(urls) > 500:
        st.error("Batch limit is 500 URLs.")
        return
    results = []
    invalid = []
    progress = st.progress(0)
    for index, url in enumerate(urls):
        valid, reason = validate_url_input(url)
        if valid:
            try:
                results.append(scan_url(url, models, columns))
            except Exception as exc:
                invalid.append({"URL": url, "Reason": f"Could not analyze: {exc}"})
        else:
            invalid.append({"URL": url, "Reason": reason})
        progress.progress((index + 1) / len(urls))
    st.session_state["batch_results"] = results
    st.session_state["batch_invalid"] = invalid
    _show_batch_table(results)


def _show_batch_table(results: list[dict]) -> None:
    if not results:
        st.info("No valid URLs in this batch.")
        return
    frame = _result_frame(results)
    selected = st.multiselect("Filter by verdict", sorted(frame["Verdict"].unique()), default=sorted(frame["Verdict"].unique()))
    displayed = frame[frame["Verdict"].isin(selected)]
    st.dataframe(displayed, hide_index=True, use_container_width=True)
    st.download_button(
        "Download filtered results as CSV",
        displayed.to_csv(index=False).encode("utf-8"),
        file_name="url-shield-batch-results.csv",
        mime="text/csv",
    )
    invalid = st.session_state.get("batch_invalid", [])
    if invalid:
        with st.expander(f"{len(invalid)} invalid or failed row(s)"):
            st.dataframe(pd.DataFrame(invalid), hide_index=True, use_container_width=True)


def _dashboard() -> None:
    st.title("Scan history & dashboard")
    history = st.session_state.get("history", [])
    if not history:
        st.info("Your scan history is empty. Scans are held only in this browser session and are not saved to disk.")
        return
    frame = _result_frame(history)
    left, right = st.columns(2)
    with left:
        st.subheader("Verdict counts")
        counts = frame["Verdict"].value_counts()
        st.plotly_chart(go.Figure(go.Bar(x=counts.index, y=counts.values, marker_color="#2563eb")).update_layout(height=300), use_container_width=True)
    with right:
        st.subheader("Risk-score distribution")
        st.plotly_chart(go.Figure(go.Histogram(x=frame["Risk score"], nbinsx=10, marker_color="#d97706")).update_layout(height=300, xaxis_title="Risk score (0–100)"), use_container_width=True)
    st.dataframe(frame, hide_index=True, use_container_width=True)
    if st.button("Clear session history"):
        st.session_state["history"] = []
        st.rerun()


def _learn_mode() -> None:
    st.title("Learn: recognize malicious links")
    with st.expander("Phishing", expanded=True):
        st.write("Phishing links impersonate trusted organizations to steal credentials, payment details, or one-time codes. Check the exact hostname and reach services through a saved bookmark or official app.")
    with st.expander("Malware"):
        st.write("Malware links try to get you to download or run harmful files. Avoid unexpected downloads, keep software updated, and never disable security protections to install something.")
    with st.expander("Defacement"):
        st.write("A defaced site has been changed without authorization. A legitimate domain can still host compromised content, so treat unexpected instructions, payment requests, and downloads cautiously.")
    st.subheader("Spot the phishing URL")
    quiz = [
        ("Which URL is the strongest red flag?", ["https://www.wikipedia.org/", "https://paypal.com.security-check.example/login", "https://docs.python.org/"], 1, "The real hostname is `security-check.example`; paypal.com is only a subdomain label."),
        ("What is the safest way to reach your bank?", ["Use the link in an unexpected SMS", "Search for a phone number in the message", "Open the bank’s official app or type a saved address"], 2, "Use an independently verified official app or address."),
        ("Does HTTPS prove a website is trustworthy?", ["Yes, always", "No; it encrypts a connection but does not prove the operator is honest", "Only on mobile"], 1, "HTTPS is useful but does not validate intent or ownership."),
    ]
    answers = []
    with st.form("quiz"):
        for index, (question, options, _, _) in enumerate(quiz):
            answer = st.radio(question, options, key=f"quiz_{index}")
            answers.append(options.index(answer))
        submitted = st.form_submit_button("Check my score")
    if submitted:
        score = sum(answer == item[2] for answer, item in zip(answers, quiz))
        st.success(f"You scored {score}/{len(quiz)}.")
        for item in quiz:
            st.caption(item[3])
    st.caption("Awareness tip: verify the registrable domain, not just familiar words somewhere in a URL.")


def _qr_tool() -> None:
    st.title("QR link check")
    st.write("Decode a QR image locally, then inspect the extracted URL as text. The destination is not opened.")
    image = st.file_uploader("Upload QR image", type=["png", "jpg", "jpeg", "bmp"], key="qr_image")
    if image is None:
        return
    try:
        import cv2
        import numpy as np

        data = np.frombuffer(image.getvalue(), dtype=np.uint8)
        decoded = cv2.imdecode(data, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        text, _, _ = detector.detectAndDecode(decoded)
    except ImportError:
        st.error("QR decoding requires opencv-python-headless. Install the optional dependency from requirements.txt.")
        return
    except Exception as exc:
        st.error(f"Could not decode this QR image: {exc}")
        return
    if not text:
        st.warning("No readable QR code was found.")
        return
    st.text_input("Extracted URL text (not opened)", value=text, key="qr_url")
    valid, reason = validate_url_input(text)
    if not valid:
        st.warning(reason)
        return
    models, columns, _ = load_models(str(ROOT))
    if st.button("Scan extracted URL"):
        result = scan_url(text, models, columns)
        st.session_state["last_scan"] = result
        st.session_state.setdefault("history", []).insert(0, result)
        _render_scan(result, models, columns)


def main() -> None:
    models, columns, load_errors = load_models(str(ROOT))
    with st.sidebar:
        st.title("🛡️ URL Shield")
        page = st.radio("Navigate", ["Single scan", "Batch scan", "Dashboard", "Learn mode", "QR scan"])
        if load_errors:
            with st.expander("Model setup", expanded=not models):
                st.caption("The app can still start, but trained predictions need the supplied trusted model artifacts.")
                for error in load_errors:
                    st.warning(error)
    if page == "Single scan":
        _single_scan(models, columns)
    elif page == "Batch scan":
        _batch_scan(models, columns)
    elif page == "Dashboard":
        _dashboard()
    elif page == "Learn mode":
        _learn_mode()
    else:
        _qr_tool()


if __name__ == "__main__":
    main()
