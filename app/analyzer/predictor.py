"""
Model loading and inference.

Loads the trained scikit-learn model (model.pkl) plus the feature order that
was used to train it (features.json), and exposes predict_proba(url).

Two safety properties matter here:

  1. GRACEFUL DEGRADATION. If model.pkl is missing (the student has not run
     train.py yet), nothing crashes: predict_proba() returns None and the
     hybrid layer falls back to a heuristic-only verdict.

  2. NO TRAIN/SERVE SKEW. features.json records the exact column order used at
     training time. On load we compare it with FEATURE_NAMES from features.py
     and refuse to use the model if they differ, because silently feeding the
     columns in a different order would produce confident nonsense.
"""

from __future__ import annotations

import json
import threading

import joblib
import numpy as np

from app.analyzer.features import FEATURE_NAMES, extract_vector
from app.config import FEATURES_PATH, METRICS_PATH, MODEL_PATH

# Module-level cache so the model is unpickled once, not on every request.
_MODEL = None
_MODEL_NAME = ""
_FEATURE_ORDER: list[str] = []
_LOAD_ERROR = ""
_LOADED = False
_LOCK = threading.Lock()


def _load() -> None:
    """
    Load model.pkl and features.json exactly once (thread-safe).

    Any failure is recorded in _LOAD_ERROR and leaves _MODEL as None rather
    than propagating - a missing model must degrade, not crash.
    """
    global _MODEL, _MODEL_NAME, _FEATURE_ORDER, _LOAD_ERROR, _LOADED

    with _LOCK:
        if _LOADED:
            return
        _LOADED = True

        if not MODEL_PATH.exists():
            _LOAD_ERROR = (
                f"model file not found at {MODEL_PATH} - run: python -m app.ml.train"
            )
            return
        if not FEATURES_PATH.exists():
            _LOAD_ERROR = f"features.json not found at {FEATURES_PATH} - run: python -m app.ml.train"
            return

        try:
            with open(FEATURES_PATH, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            order = payload.get("feature_names", payload if isinstance(payload, list) else [])

            # The contract check that prevents train/serve skew.
            if list(order) != list(FEATURE_NAMES):
                _LOAD_ERROR = (
                    "features.json does not match FEATURE_NAMES in features.py "
                    "(the feature set changed since training) - retrain with: "
                    "python -m app.ml.train"
                )
                return

            model = joblib.load(MODEL_PATH)
            _FEATURE_ORDER = list(order)
            _MODEL = model
            _MODEL_NAME = payload.get("model_name", type(model).__name__)
        except Exception as exc:
            _MODEL = None
            _LOAD_ERROR = f"could not load model: {exc}"


def is_loaded() -> bool:
    """True when a usable model is in memory."""
    _load()
    return _MODEL is not None


def load_error() -> str:
    """Why the model is unavailable ('' when it loaded fine)."""
    _load()
    return _LOAD_ERROR


def model_name() -> str:
    """Name of the selected algorithm, e.g. 'RandomForest'."""
    _load()
    return _MODEL_NAME


def predict_proba(url: str) -> float | None:
    """
    Probability that `url` is phishing, in the range 0.0 - 1.0.

    Returns None when no model is available, which the hybrid layer treats as
    "ML unavailable" and handles by re-weighting the remaining signals.
    """
    _load()
    if _MODEL is None:
        return None

    try:
        vector = extract_vector(url)
        matrix = np.asarray([vector], dtype=float)
        # Column 1 is the positive (phishing) class, because the labels are
        # 0 = benign and 1 = phishing.
        probability = float(_MODEL.predict_proba(matrix)[0][1])
        # Clamp defensively so a numerically odd model can never push the
        # hybrid score out of range.
        return max(0.0, min(1.0, probability))
    except Exception:
        return None


def get_metrics() -> dict:
    """The training metrics from metrics.json ({} if training never ran)."""
    if not METRICS_PATH.exists():
        return {}
    try:
        with open(METRICS_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def reset() -> None:
    """Force the next call to re-read model.pkl (used after retraining/tests)."""
    global _MODEL, _MODEL_NAME, _FEATURE_ORDER, _LOAD_ERROR, _LOADED
    with _LOCK:
        _MODEL = None
        _MODEL_NAME = ""
        _FEATURE_ORDER = []
        _LOAD_ERROR = ""
        _LOADED = False
