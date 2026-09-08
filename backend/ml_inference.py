"""
ml_inference.py
===============
Loads the trained IsolationForest and OrdinalEncoder once at Lambda cold-start
and exposes a single function: score_event().

Imports feature_contract for extraction — never reimplements it here.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Locate ml/ relative to this file whether running in Lambda (/var/task/)
# or locally (backend/ sibling of ml/)
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
_ML_DIR = (_HERE / "ml") if (_HERE / "ml").exists() else (_HERE.parent / "ml")
sys.path.insert(0, str(_ML_DIR))

from feature_contract import (  # noqa: E402
    FEATURE_NAMES,
    CATEGORICAL_FEATURES,
    extract_features,
    build_dataframe,
)
from config import MODEL_PATH, ENCODER_PATH, ANOMALY_SCORE_THRESHOLD  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton load — happens once per Lambda container lifetime
# ---------------------------------------------------------------------------
_encoder = None
_model   = None


def _load_artefacts() -> tuple:
    global _encoder, _model
    if _encoder is None:
        logger.info("Loading encoder from %s", ENCODER_PATH)
        _encoder = joblib.load(ENCODER_PATH)
    if _model is None:
        logger.info("Loading model from %s", MODEL_PATH)
        _model = joblib.load(MODEL_PATH)
    return _encoder, _model


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_event(cloudtrail_event: dict[str, Any]) -> dict[str, Any]:
    """
    Full ML scoring for a single CloudTrail event.

    Parameters
    ----------
    cloudtrail_event : dict
        Raw CloudTrail event dict (EventBridge envelope or flat).

    Returns
    -------
    dict with keys:
        features      : dict[str, Any]  — extracted (pre-encoded) feature values
        encoded       : list[float]     — encoded feature vector (for SHAP)
        anomaly_score : float           — decision_function score (<0 = anomalous)
        is_anomaly    : bool
        prediction    : int             — 1 (normal) or -1 (anomaly)
    """
    encoder, model = _load_artefacts()

    # 1. Extract named features from raw event
    features = extract_features(cloudtrail_event)

    # 2. Encode categorical columns using the saved OrdinalEncoder
    cat_df  = pd.DataFrame([[
        features["eventName"],
        features["userIdentitytype"],
        features["awsRegion"],
    ]], columns=CATEGORICAL_FEATURES)

    cat_enc = encoder.transform(cat_df)  # shape (1, 3)

    # 3. Build full feature vector in canonical FEATURE_NAMES order
    # FEATURE_NAMES = ["eventName", "hour", "userIdentitytype", "awsRegion", "isRoot"]
    feature_vector = np.array([[
        cat_enc[0, 0],            # eventName encoded
        float(features["hour"]),  # hour (numeric)
        cat_enc[0, 1],            # userIdentitytype encoded
        cat_enc[0, 2],            # awsRegion encoded
        float(features["isRoot"]),# isRoot (binary)
    ]], dtype=np.float64)

    # 4. Predict
    prediction    = int(model.predict(feature_vector)[0])
    anomaly_score = float(model.decision_function(feature_vector)[0])
    is_anomaly    = prediction == -1 and anomaly_score < ANOMALY_SCORE_THRESHOLD

    logger.info(
        "score_event: eventName=%s anomaly_score=%.4f is_anomaly=%s",
        features["eventName"], anomaly_score, is_anomaly,
    )

    return {
        "features":      features,
        "encoded":       feature_vector[0].tolist(),
        "anomaly_score": anomaly_score,
        "is_anomaly":    is_anomaly,
        "prediction":    prediction,
    }
