"""Train app-compatible URL classifiers from a labeled CSV without network access.

CSV format: ``url,label`` where labels are benign, phishing, malware, or
defacement. Artifacts are written under ``trained_models`` by default.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from urlshield.features import FEATURE_COLUMNS, extract_features, validate_url_input

LABELS = {"benign", "phishing", "malware", "defacement"}


def load_training_data(csv_path: Path) -> tuple[pd.DataFrame, pd.Series]:
    """Read and validate labeled URL text; this function never visits URLs."""
    data = pd.read_csv(csv_path, dtype=str)
    if "label" not in data.columns and "type" in data.columns:
        data = data.rename(columns={"type": "label"})
    missing_columns = {"url", "label"} - set(data.columns)
    if missing_columns:
        raise ValueError(
            "CSV must contain url and label columns; missing: "
            + ", ".join(sorted(missing_columns))
        )

    data = data.dropna(subset=["url", "label"]).copy()
    data["url"] = data["url"].str.strip()
    data["label"] = data["label"].str.strip().str.lower()
    data = data[(data["url"] != "") & (data["label"] != "")]
    invalid_labels = sorted(set(data["label"]) - LABELS)
    if invalid_labels:
        raise ValueError(
            "Unsupported labels: " + ", ".join(invalid_labels)
            + ". Use benign, phishing, malware, and defacement."
        )

    invalid_rows = []
    for index, url in data["url"].items():
        valid, reason = validate_url_input(url)
        if not valid:
            invalid_rows.append((index, reason))
    if invalid_rows:
        print(f"Skipping {len(invalid_rows)} row(s) with invalid URL text.")
        data = data.drop(index=[index for index, _ in invalid_rows])

    conflicts = data.groupby("url")["label"].nunique()
    conflicting_urls = conflicts[conflicts > 1].index.tolist()
    if conflicting_urls:
        print(
            f"Skipping all rows for {len(conflicting_urls)} URL(s) with conflicting labels."
        )
        data = data[~data["url"].isin(conflicting_urls)]

    duplicate_rows = int(data.duplicated(subset=["url"]).sum())
    data = data.drop_duplicates(subset=["url"], keep="first")
    if duplicate_rows:
        print(f"Removed {duplicate_rows} duplicate URL row(s).")
    observed = set(data["label"])
    missing_labels = sorted(LABELS - observed)
    if missing_labels:
        raise ValueError("Training CSV has no examples for: " + ", ".join(missing_labels))
    counts = data["label"].value_counts()
    too_small = {label: int(count) for label, count in counts.items() if count < 5}
    if too_small:
        details = ", ".join(f"{label}: {count}" for label, count in sorted(too_small.items()))
        raise ValueError(
            "At least 5 distinct URLs per class are required for a stratified train/test split. "
            f"Insufficient counts: {details}"
        )

    print(f"Using {len(data):,} unique valid URLs.")
    print("Class counts:")
    for label, count in counts.sort_index().items():
        print(f"  {label}: {count:,}")
    features = pd.DataFrame(
        [extract_features(url) for url in data["url"]],
        columns=FEATURE_COLUMNS,
        dtype=np.float64,
    )
    return features, data["label"].reset_index(drop=True)


def create_models(random_seed: int = 42, include_mlp: bool = True) -> dict[str, Any]:
    """Create the model families expected by URL Shield."""
    models = {
        "best_url_model.pkl": ExtraTreesClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=random_seed,
            n_jobs=-1,
        ),
    }
    if include_mlp:
        models["mlp_url_model.pkl"] = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    MLPClassifier(
                        hidden_layer_sizes=(64, 32),
                        batch_size=1024,
                        max_iter=100,
                        early_stopping=True,
                        n_iter_no_change=5,
                        verbose=True,
                        random_state=random_seed,
                    ),
                ),
            ]
        )
    return models


def train(
    csv_path: Path,
    output_dir: Path,
    random_seed: int = 42,
    include_mlp: bool = True,
) -> None:
    """Train, evaluate, and save app-compatible model artifacts."""
    features, labels = load_training_data(csv_path)
    x_train, x_test, y_train, y_test = train_test_split(
        features.to_numpy(),
        labels,
        test_size=0.2,
        random_state=random_seed,
        stratify=labels,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(FEATURE_COLUMNS, output_dir / "url_feature_columns.pkl")
    trained = create_models(random_seed, include_mlp)
    for filename, model in trained.items():
        print(f"\nTraining {filename}...")
        model.fit(x_train, y_train)
        print(f"Evaluation for {filename} (held-out 20%):")
        print(
            classification_report(
                y_test,
                model.predict(x_test),
                labels=sorted(LABELS),
                zero_division=0,
            )
        )
        joblib.dump(model, output_dir / filename)
        print(f"Saved {output_dir / filename}")
    print(f"Saved app-compatible artifacts to: {output_dir.resolve()}")
    print("Review hold-out metrics and test thoroughly before using these models.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="CSV containing url,label columns")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("trained_models"),
        help="Output directory (default: trained_models; does not overwrite root artifacts)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument(
        "--skip-mlp",
        action="store_true",
        help="Train only the tree model; the app can use it without an MLP model",
    )
    args = parser.parse_args()
    train(args.dataset, args.output_dir, args.seed, include_mlp=not args.skip_mlp)


if __name__ == "__main__":
    main()
