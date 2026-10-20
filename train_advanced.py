"""Optional research script for training separate, richer URL models.

Input CSV must contain ``url`` and ``label`` columns. Outputs are deliberately
named separately so these models cannot be mistaken for the app's 23-feature
pre-trained artifacts.
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import re
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from urlshield.features import FEATURE_COLUMNS, extract_features
from urlshield.signals import POPULAR_BRANDS

ADVANCED_COLUMNS = FEATURE_COLUMNS + [
    "url_entropy", "tld_length", "subdomain_count", "digit_letter_ratio",
    "brand_similarity",
]


def advanced_features(url: str) -> list[float]:
    """Append five URL-text features to the established 23-feature vector."""
    cleaned = url.strip().replace("www.", "")
    parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}")
    host = (parsed.hostname or "").lower()
    labels = [label for label in host.split(".") if label]
    tld = labels[-1] if len(labels) > 1 else ""
    counts = Counter(cleaned)
    length = max(1, len(cleaned))
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    digits = sum(character.isdigit() for character in host)
    letters = sum(character.isalpha() for character in host)
    ratio = digits / max(1, letters)
    normalized = re.sub(r"[^a-z0-9]", "", host.split(".")[0])
    similarity = max(
        (SequenceMatcher(None, normalized, brand).ratio() for brand in POPULAR_BRANDS),
        default=0.0,
    )
    try:
        ipaddress.ip_address(host.strip("[]"))
        subdomain_count = 0
    except ValueError:
        subdomain_count = max(0, len(labels) - 2)
    return extract_features(cleaned) + [entropy, len(tld), subdomain_count, ratio, similarity]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="CSV containing url,label columns")
    parser.add_argument("--output-dir", type=Path, default=Path("advanced_models"))
    args = parser.parse_args()
    data = pd.read_csv(args.dataset)
    missing = {"url", "label"} - set(data.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(sorted(missing))}")
    data = data.dropna(subset=["url", "label"])
    if data["label"].nunique() < 2:
        raise ValueError("Training requires at least two distinct labels.")
    x = pd.DataFrame([advanced_features(str(value)) for value in data["url"]], columns=ADVANCED_COLUMNS)
    y = data["label"].astype(str).str.lower()
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, random_state=42, stratify=y
    )
    models = {
        "tree": ExtraTreesClassifier(n_estimators=300, class_weight="balanced", random_state=42),
        "forest": RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42),
        "mlp": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=500, random_state=42)),
        ]),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(ADVANCED_COLUMNS, args.output_dir / "advanced_feature_columns.pkl")
    for name, model in models.items():
        model.fit(x_train, y_train)
        print(f"\n{name} evaluation")
        print(classification_report(y_test, model.predict(x_test), zero_division=0))
        joblib.dump(model, args.output_dir / f"advanced_{name}_model.pkl")
    print(f"Advanced models saved to {args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
