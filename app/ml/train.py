"""
Model training and evaluation.

Trains TWO classifiers on the same URL-string features and keeps whichever
scores the higher test F1:

    Model A : StandardScaler -> LogisticRegression(max_iter=1000,
                                                   class_weight="balanced")
              A linear model. Scaling matters because url_length runs to ~300
              while is_https is 0/1, and an unscaled logistic regression would
              be dominated by the large-magnitude columns.

    Model B : RandomForestClassifier(n_estimators=300, random_state=42,
                                     class_weight="balanced")
              300 decision trees voting. Needs no scaling and captures
              interactions such as "high entropy AND a risky TLD".

Reported for both: accuracy, precision, recall, F1, ROC-AUC, the confusion
matrix and a 5-fold stratified cross-validated mean F1. Cross-validation is the
honest number - a single train/test split on 2400 rows is noisy.

Usage
-----
    python -m app.ml.train                       # use the generated dataset
    python -m app.ml.train --csv real_data.csv   # use any CSV with url,label
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.analyzer.features import FEATURE_NAMES, extract_vector
from app.config import DATASET_PATH, FEATURES_PATH, METRICS_PATH, MODEL_PATH

RANDOM_STATE = 42
TEST_SIZE = 0.20
CV_FOLDS = 5

# Above this accuracy the synthetic dataset is probably too easy; we say so
# out loud rather than quietly reporting a flattering number.
SUSPICIOUSLY_HIGH_ACCURACY = 0.99


def load_dataset(csv_path: Path) -> pd.DataFrame:
    """Read a url,label CSV, validate it and drop duplicate URLs."""
    if not csv_path.exists():
        print(f"ERROR: dataset not found at {csv_path}", file=sys.stderr)
        print("Generate it first:  python -m app.ml.make_dataset", file=sys.stderr)
        raise SystemExit(1)

    frame = pd.read_csv(csv_path, encoding="utf-8")

    missing = {"url", "label"} - set(frame.columns)
    if missing:
        print(f"ERROR: {csv_path} is missing column(s): {', '.join(sorted(missing))}",
              file=sys.stderr)
        print("The CSV must have a header row with exactly: url,label", file=sys.stderr)
        raise SystemExit(1)

    before = len(frame)
    frame = frame.dropna(subset=["url", "label"])
    frame["url"] = frame["url"].astype(str).str.strip()
    frame = frame[frame["url"] != ""]
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    frame = frame.dropna(subset=["label"])
    frame["label"] = frame["label"].astype(int)
    frame = frame[frame["label"].isin([0, 1])]

    # De-duplicate case-insensitively: the same URL in both train and test
    # would leak and inflate every metric.
    frame = frame.drop_duplicates(subset=frame["url"].str.lower().name, keep="first")
    frame = frame.loc[~frame["url"].str.lower().duplicated(keep="first")]

    removed = before - len(frame)
    if removed:
        print(f"  Removed {removed} duplicate/invalid row(s)")

    if frame["label"].nunique() < 2:
        print("ERROR: the dataset contains only one class - cannot train.", file=sys.stderr)
        raise SystemExit(1)

    return frame.reset_index(drop=True)


def build_matrix(urls: list[str]) -> np.ndarray:
    """
    Turn URL strings into the feature matrix.

    Uses the same extract_vector() that serves live predictions, so training
    and serving can never disagree about what a feature means.
    """
    return np.asarray([extract_vector(u) for u in urls], dtype=float)


def evaluate(name: str, model, X_train, X_test, y_train, y_test, X_all, y_all) -> dict:
    """Fit one model, score it on the held-out split and cross-validate it."""
    print(f"\n  Training {name} ...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(model, X_all, y_all, cv=cv, scoring="f1", n_jobs=1)

    metrics = {
        "model": name,
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "confusion_matrix": {
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
        },
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std": float(cv_scores.std()),
        "cv_f1_folds": [round(float(s), 4) for s in cv_scores],
    }

    print(f"    accuracy  {metrics['accuracy']:.4f}   "
          f"precision {metrics['precision']:.4f}   "
          f"recall {metrics['recall']:.4f}")
    print(f"    F1        {metrics['f1']:.4f}   "
          f"ROC-AUC   {metrics['roc_auc']:.4f}   "
          f"CV F1 {metrics['cv_f1_mean']:.4f} (+/- {metrics['cv_f1_std']:.4f})")
    return metrics


def print_confusion(metrics: dict) -> None:
    """Print one confusion matrix with labelled axes."""
    cm = metrics["confusion_matrix"]
    print(f"\n  Confusion matrix - {metrics['model']}")
    print("                      predicted")
    print("                  benign   phishing")
    print(f"    actual benign   {cm['true_negative']:>5}   {cm['false_positive']:>8}"
          f"    <- {cm['false_positive']} false alarms")
    print(f"    actual phishing {cm['false_negative']:>5}   {cm['true_positive']:>8}"
          f"    <- {cm['false_negative']} missed attacks")


def print_comparison(all_metrics: list[dict], winner: str) -> None:
    """Side-by-side comparison table of every model trained."""
    print("\n" + "=" * 78)
    print("  MODEL COMPARISON")
    print("=" * 78)
    header = f"  {'Model':<22}{'Acc':>8}{'Prec':>8}{'Recall':>8}{'F1':>8}{'ROC-AUC':>10}{'CV F1':>9}"
    print(header)
    print("  " + "-" * 74)
    for m in all_metrics:
        marker = "  <-- selected" if m["model"] == winner else ""
        print(f"  {m['model']:<22}"
              f"{m['accuracy']:>8.4f}{m['precision']:>8.4f}{m['recall']:>8.4f}"
              f"{m['f1']:>8.4f}{m['roc_auc']:>10.4f}{m['cv_f1_mean']:>9.4f}{marker}")
    print("=" * 78)


def print_feature_importance(forest: RandomForestClassifier, logreg: Pipeline) -> dict:
    """Print and return the interpretability tables for the project report."""
    print("\n" + "=" * 78)
    print("  FEATURE IMPORTANCE  (which signals actually drive the decision)")
    print("=" * 78)

    importances = forest.feature_importances_
    ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda p: p[1], reverse=True)

    print("\n  RandomForest - top 10 by Gini importance")
    print(f"  {'rank':<6}{'feature':<28}{'importance':>12}")
    print("  " + "-" * 46)
    top_forest = []
    for rank, (name, value) in enumerate(ranked[:10], start=1):
        bar = "#" * max(1, int(value * 120))
        print(f"  {rank:<6}{name:<28}{value:>12.4f}  {bar}")
        top_forest.append({"feature": name, "importance": round(float(value), 6)})

    coefficients = logreg.named_steps["clf"].coef_[0]
    by_absolute = sorted(zip(FEATURE_NAMES, coefficients),
                         key=lambda p: abs(p[1]), reverse=True)

    print("\n  LogisticRegression - top 10 coefficients")
    print("  (positive pushes towards PHISHING, negative towards BENIGN)")
    print(f"  {'rank':<6}{'feature':<28}{'coefficient':>13}{'  direction'}")
    print("  " + "-" * 60)
    top_logreg = []
    for rank, (name, value) in enumerate(by_absolute[:10], start=1):
        direction = "-> phishing" if value > 0 else "-> benign"
        print(f"  {rank:<6}{name:<28}{value:>13.4f}  {direction}")
        top_logreg.append({"feature": name, "coefficient": round(float(value), 6),
                           "direction": "phishing" if value > 0 else "benign"})

    return {"random_forest_top10": top_forest, "logistic_regression_top10": top_logreg}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m app.ml.train",
        description="Train the LTAT phishing classifier on URL-string features.",
    )
    parser.add_argument(
        "--csv", metavar="PATH", default=str(DATASET_PATH),
        help="path to a dataset CSV with url,label columns "
             "(default: the generated app/ml/dataset.csv)",
    )
    args = parser.parse_args()
    csv_path = Path(args.csv)

    print("=" * 78)
    print("  LTAT  -  Model training")
    print("=" * 78)

    # ---------------- data ----------------
    print(f"\n  Dataset: {csv_path}")
    frame = load_dataset(csv_path)

    benign = int((frame["label"] == 0).sum())
    phishing = int((frame["label"] == 1).sum())
    print(f"  Rows after cleaning: {len(frame)}  "
          f"(benign {benign}, phishing {phishing})")
    print(f"  Features: {len(FEATURE_NAMES)} URL-string features "
          f"(no certificate data - see README)")

    urls = frame["url"].tolist()
    X = build_matrix(urls)
    y = frame["label"].to_numpy()

    if not np.isfinite(X).all():
        print("ERROR: feature matrix contains NaN or infinity.", file=sys.stderr)
        raise SystemExit(1)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    print(f"  Split: {len(X_train)} train / {len(X_test)} test "
          f"(stratified, random_state={RANDOM_STATE})")

    # ---------------- models ----------------
    logreg = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced",
                                   random_state=RANDOM_STATE)),
    ])
    forest = RandomForestClassifier(
        n_estimators=300, random_state=RANDOM_STATE,
        class_weight="balanced", n_jobs=-1,
    )

    print("\n" + "-" * 78)
    print("  TRAINING")
    print("-" * 78)

    logreg_metrics = evaluate("LogisticRegression", logreg,
                              X_train, X_test, y_train, y_test, X, y)
    forest_metrics = evaluate("RandomForest", forest,
                              X_train, X_test, y_train, y_test, X, y)

    print_confusion(logreg_metrics)
    print_confusion(forest_metrics)

    # ---------------- selection ----------------
    all_metrics = [logreg_metrics, forest_metrics]
    if forest_metrics["f1"] >= logreg_metrics["f1"]:
        best_name, best_model, best_metrics = "RandomForest", forest, forest_metrics
    else:
        best_name, best_model, best_metrics = "LogisticRegression", logreg, logreg_metrics

    print_comparison(all_metrics, best_name)
    importance = print_feature_importance(forest, logreg)

    # ---------------- honesty check ----------------
    warnings: list[str] = []
    if best_metrics["accuracy"] > SUSPICIOUSLY_HIGH_ACCURACY:
        warning = (
            f"Test accuracy {best_metrics['accuracy']:.4f} is above "
            f"{SUSPICIOUSLY_HIGH_ACCURACY}. The synthetic dataset is probably too "
            "separable, so this number will NOT hold on real-world phishing URLs. "
            "Retrain on a real PhishTank/Kaggle CSV with --csv for a trustworthy "
            "estimate."
        )
        warnings.append(warning)
        print("\n" + "!" * 78)
        print("  WARNING - the metrics above may be optimistic")
        print("!" * 78)
        for line in _wrap(warning, 74):
            print(f"  {line}")

    # ---------------- persist ----------------
    joblib.dump(best_model, MODEL_PATH)

    with open(FEATURES_PATH, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "feature_names": FEATURE_NAMES,
                "n_features": len(FEATURE_NAMES),
                "model_name": best_name,
                "note": "Feature order is a contract between train.py and "
                        "predictor.py. Never reorder without retraining.",
            },
            handle, indent=2,
        )

    metrics_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(csv_path),
        "dataset_rows": len(frame),
        "dataset_benign": benign,
        "dataset_phishing": phishing,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "cv_folds": CV_FOLDS,
        "n_features": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "selected_model": best_name,
        "selection_criterion": "highest test F1",
        "models": all_metrics,
        "feature_importance": importance,
        "warnings": warnings,
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as handle:
        json.dump(metrics_payload, handle, indent=2)

    print("\n" + "=" * 78)
    print("  SAVED")
    print("=" * 78)
    print(f"  Selected model : {best_name}  (test F1 = {best_metrics['f1']:.4f})")
    print(f"  model.pkl      : {MODEL_PATH}")
    print(f"  features.json  : {FEATURES_PATH}")
    print(f"  metrics.json   : {METRICS_PATH}")
    print("\n  Next step:  python -m uvicorn app.main:app --host 127.0.0.1 --port 8000")
    print("=" * 78)


def _wrap(text: str, width: int) -> list[str]:
    """Tiny word-wrapper so the warning block stays inside the box."""
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


if __name__ == "__main__":
    main()
