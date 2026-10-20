"""Load and use the pre-trained URL models without modifying them."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import streamlit as st

from .features import FEATURE_COLUMNS, extract_features

MODEL_FILES = {
    "Tree model": "best_url_model.pkl",
    "MLP model": "mlp_url_model.pkl",
}
FEATURE_FILE = "url_feature_columns.pkl"
CLASSES = ("benign", "defacement", "malware", "phishing")


@st.cache_resource(show_spinner=False)
def load_models(model_dir: str = ".") -> tuple[dict[str, Any], list[str], list[str]]:
    """Load available joblib artifacts and return models, feature order, errors."""
    root = Path(model_dir)
    trained_root = root / "trained_models"
    root_has_features = (root / FEATURE_FILE).is_file()
    trained_has_model = any((trained_root / filename).is_file() for filename in MODEL_FILES.values())
    if root_has_features and any((root / filename).is_file() for filename in MODEL_FILES.values()):
        artifact_root = root
    elif (trained_root / FEATURE_FILE).is_file() and trained_has_model:
        artifact_root = trained_root
    else:
        artifact_root = root
    models: dict[str, Any] = {}
    errors: list[str] = []
    feature_path = artifact_root / FEATURE_FILE
    feature_columns: list[str] = FEATURE_COLUMNS

    if feature_path.exists():
        try:
            loaded_features = joblib.load(feature_path)
            if list(loaded_features) != FEATURE_COLUMNS:
                errors.append(f"{FEATURE_FILE} does not match the required 23-feature order.")
                feature_columns = []
            else:
                feature_columns = list(loaded_features)
        except Exception as exc:
            errors.append(f"Could not load {FEATURE_FILE}: {exc}")
            feature_columns = []
    else:
        errors.append(f"Missing {FEATURE_FILE}; the expected feature order is used.")

    for label, filename in MODEL_FILES.items():
        path = artifact_root / filename
        if not path.exists():
            errors.append(f"Missing {filename} in {artifact_root}.")
            continue
        if not feature_columns:
            errors.append(f"Skipped {filename}: feature-column order is incompatible.")
            continue
        try:
            model = joblib.load(path)
            expected_count = getattr(model, "n_features_in_", len(feature_columns))
            if expected_count != len(feature_columns):
                errors.append(f"Skipped {filename}: it expects {expected_count} features, not {len(feature_columns)}.")
                continue
            models[label] = model
        except Exception as exc:
            errors.append(f"Could not load {filename}: {exc}")
    return models, feature_columns, errors


def predict_one(model: Any, url: str, columns: list[str]) -> dict:
    """Predict one URL and normalize class probabilities to known labels."""
    row = np.asarray([extract_features(url)], dtype=float)
    if row.shape[1] != len(columns):
        raise ValueError(f"Model expects {len(columns)} features but extractor returned {row.shape[1]}.")
    predicted = str(model.predict(row)[0]).lower()
    classes = [str(item).lower() for item in getattr(model, "classes_", CLASSES)]
    probabilities = {label: 0.0 for label in CLASSES}
    if hasattr(model, "predict_proba"):
        raw = model.predict_proba(row)[0]
        for label, probability in zip(classes, raw):
            if label in probabilities:
                probabilities[label] = float(probability)
    else:
        probabilities[predicted] = 1.0
    total = sum(probabilities.values())
    if total > 0:
        probabilities = {label: value / total for label, value in probabilities.items()}
    return {
        "verdict": predicted if predicted in CLASSES else "unknown",
        "probabilities": probabilities,
        "confidence": max(probabilities.values(), default=0.0),
    }


def heuristic_prediction(url: str, red_flags: list[dict]) -> dict:
    """Provide a clearly labeled pattern-only fallback when no model is loaded."""
    score = min(95, 6 + 15 * len(red_flags))
    probabilities = {
        "benign": max(0.05, 1.0 - score / 100),
        "phishing": score / 100,
        "malware": 0.0,
        "defacement": 0.0,
    }
    total = sum(probabilities.values())
    probabilities = {key: value / total for key, value in probabilities.items()}
    return {
        "verdict": "phishing" if score >= 40 else "benign",
        "probabilities": probabilities,
        "confidence": max(probabilities.values()),
        "risk_score": score,
        "source": "URL-pattern heuristic (trained model files unavailable)",
    }


def risk_score(probabilities: dict[str, float]) -> int:
    """Aggregate non-benign class probabilities into an interpretable score."""
    return round(100 * sum(probabilities.get(label, 0.0) for label in ("phishing", "malware", "defacement")))
