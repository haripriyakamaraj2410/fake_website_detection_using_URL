# URL Shield: AI Malicious URL Detector

URL Shield analyzes URL text for patterns associated with phishing, malware, and
defacement. A standard scan never resolves the host, opens a connection, downloads
content, or executes anything from the URL. The trained models, when supplied, are
loaded as-is; the project does not retrain or alter them.

> **Prediction from URL patterns only. Not a guarantee of safety.**

## Project structure

```text
cyber/
├── app.py                         # Streamlit UI and application flow
├── requirements.txt
├── train_models.py                # Train the app-compatible 23-feature models
├── train_advanced.py              # Optional, separate richer-feature training utility
├── url_feature_columns.pkl        # Supply the existing model artifact here
├── best_url_model.pkl             # Supply the existing tree model here
├── mlp_url_model.pkl              # Supply the existing MLP pipeline here
├── tests/
│   └── test_features.py
└── urlshield/
    ├── __init__.py
    ├── assistant.py               # Optional Claude integration
    ├── features.py                # 23-feature extractor
    ├── live_checks.py             # Opt-in DNS/TLS/HEAD checks
    ├── models.py                  # Artifact loading and predictions
    ├── precautions.py
    ├── reports.py
    └── signals.py                 # URL-text explanations and anatomy
```

The provided workspace did not contain the referenced `app.py` or trained model
files. Consequently, the extractor implements the stated feature names, order,
and preprocessing contract, but could not be compared byte-for-byte with the
missing attached extractor. Place the trusted artifacts in the project root.
The app checks the feature-column artifact against the required order and
displays a setup notice if any artifact is missing. Without trained models, it
can still scan using a visibly labeled, pattern-only heuristic; that fallback
is not a learned model result.

**Security note:** joblib/pickle artifacts can execute code when loaded. Only
load model files from a trusted source. Model files are not included in this
project.

## Run in Visual Studio Code on Windows

1. Open this project folder in VS Code.
2. Open **Terminal → New Terminal** (PowerShell) and run:

   ```powershell
   py -3.10 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

   If PowerShell blocks local activation, use the current terminal only:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1
   ```

3. Put the three existing model files in the project root:
   `best_url_model.pkl`, `mlp_url_model.pkl`, and `url_feature_columns.pkl`.
   Without them the app runs in clearly disclosed heuristic fallback mode.
4. Start the application:

   ```powershell
   python -m streamlit run app.py
   ```

5. Open the local address printed in the terminal (normally
   `http://localhost:8501`).

To run tests:

```powershell
python -m unittest discover -s tests -v
```

### Optional integrations

* **Claude assistant:** set `ANTHROPIC_API_KEY` in the VS Code terminal before
  starting Streamlit. The assistant remains hidden without a key and requires
  an explicit consent checkbox for each scan. It receives the scan verdict,
  probabilities, red/green flags, and the user's question (URL-like text in
  the question is redacted); it does not receive the scanned URL or page content.
  Optionally set `ANTHROPIC_MODEL` to a model available to your Anthropic account.
* **SHAP attribution:** install `shap` separately with `pip install shap`. If it
  is unavailable or incompatible, the app displays global tree feature
  importance when supported, not a per-URL attribution.
* **Live metadata checks:** explicitly enable the toggle on a scan. These checks
  contact the hostname for DNS and TLS-certificate metadata, try bounded WHOIS
  lookups, and send at most five HTTP `HEAD` requests to inspect a redirect
  chain. Non-public redirect destinations are blocked and response bodies are
  never read. Live checks are not model features; remote hosts can observe the
  requests and your network address. WHOIS availability and formats vary by
  registry, so domain age may be unavailable or inaccurate.
* **QR scan:** the QR image is decoded locally with OpenCV; the extracted
  destination is only analyzed as URL text unless the user opts into live checks.

### Train app-compatible models

If you do not have the original trained artifacts, you can train new ones from
a labeled CSV. The CSV must have a `url` column and either a `label` or `type`
column. Use one row per distinct URL, label every example correctly, and
include at least five unique URLs for each of the four classes: `benign`,
`phishing`, `malware`, and `defacement`. Training is entirely from URL text;
it does not open URLs. Invalid URLs and URLs with conflicting labels are
reported and skipped; duplicate URL rows are deduplicated.

From the VS Code PowerShell terminal, run:

```powershell
python train_models.py .\training_urls.csv
```

The command trains an Extra Trees classifier and a scaled MLP pipeline. The MLP
prints iteration progress, uses early stopping, a smaller network, and larger
mini-batches so it does not silently run through 500 epochs. Each completed
model is saved immediately, followed by held-out classification metrics:

```text
trained_models\
├── best_url_model.pkl
├── mlp_url_model.pkl
└── url_feature_columns.pkl
```

The app automatically loads this complete folder when root-level supplied
artifacts are absent. If the three original model files are present in the
project root, they take precedence and remain untouched. Review the
classification report and verify false negatives/positives on independent data
before relying on newly trained models. A small or unrepresentative dataset
will not produce production-quality detections.

For a faster first run, or if MLP training is too slow on your computer, train
just the tree model:

```powershell
python train_models.py .\training_urls.csv --skip-mlp
```

The app can use the tree model alone; the MLP comparison is simply unavailable.

### Optional advanced training

`train_advanced.py` is a research utility that adds five more features and
creates differently named artifacts under `advanced_models`. Those richer
models are not consumed by the default app, which expects the exact 23-feature
model contract. Use it for experimentation only unless inference is adapted
and validated to use its additional features.

## Features

* Single and batch scans, class probabilities, confidence, risk gauge, and
  side-by-side comparison of whichever supplied models are available.
* Measured URL red/green flags, URL anatomy, and model feature attribution where
  supported. Flags are based on URL text only; no site's content is inspected.
* Practical class-specific advice, account recovery checklist, country-specific
  reporting pointers, session-only scan history, dashboard charts, CSV, HTML,
  and PDF exports.
* Awareness mini-lessons and quiz, optional local QR decoding, and opt-in
  network metadata checks.

## Known limitations

* Classification quality depends entirely on the provenance, coverage, and
  currency of the supplied trained artifacts. The no-model fallback is only a
  lightweight heuristic and must not be treated as a reliable classifier.
* Feature extraction follows the stated 23-feature contract. The original
  attached extractor was not available here to verify less explicit feature
  definitions such as `abnormal_url` and suspicious-word matching.
* The anatomy parser uses a simple last-two-label domain display, not a
  public-suffix database; domains such as `example.co.uk` may be split
  imperfectly.
* URL signals cannot establish whether a website is safe. HTTPS does not prove
  legitimacy, while a benign-looking URL can still host harmful content.
* Live DNS/TLS/WHOIS/HEAD checks are optional, can fail or be blocked, and can
  expose the request to the remote host. HEAD behavior and WHOIS records vary;
  the redirect walk is capped at five requests and private/non-public targets
  are blocked.
* User-selected live checks contact the destination host; default scans do not.
  Session scan history is transient and is not persisted to a database.
* The optional assistant is a remote third-party service. Even with URL
  redaction, the scan summary and typed question leave the local application
  only after the user opts in. Do not include sensitive information in questions.
* Advanced training needs a representative, lawfully obtained labeled dataset
  and is a starting point, not a production model validation pipeline.
