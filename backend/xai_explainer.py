"""
xai_explainer.py
================
SHAP-based feature attribution for IsolationForest anomaly explanations.

Key design decisions (from audit):
  1. shap.TreeExplainer explains the raw anomaly SCORE (mean path length).
     Higher score = more normal. This is NOT a probability.

  2. POLARITY RULE:
     Negative SHAP value  = feature shortens isolation path = pushes toward ANOMALY
     Positive SHAP value  = feature lengthens isolation path = pushes toward NORMAL

     Therefore: the primary anomalous feature is the one with the MOST NEGATIVE SHAP
     value, NOT the largest absolute value.

  3. Attribution confidence = |top_negative_shap| / sum(|all_negative_shap|)
     Ranges 0–1. Low value (<0.30) means anomaly is spread across features → Uncertain.

  4. TreeExplainer is stateless relative to the model object — no pre-saved explainer needed.
     It instantiates from the model in <100ms.

Reference: verified live against model.pkl on both AttachAdministratorPolicy and
PutBucketPolicy test cases during Phase 0 audit.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import shap

logger = logging.getLogger(__name__)

# Module-level explainer cache (instantiated once per Lambda container)
_explainer = None


def _get_explainer(model) -> shap.TreeExplainer:
    global _explainer
    if _explainer is None:
        logger.info("Instantiating shap.TreeExplainer")
        _explainer = shap.TreeExplainer(model)
    return _explainer


def explain(
    model,
    feature_vector: np.ndarray,
    feature_names: list[str],
) -> dict[str, Any]:
    """
    Compute SHAP attribution for a single anomalous event.

    Parameters
    ----------
    model : IsolationForest
        The fitted model (loaded by ml_inference).
    feature_vector : np.ndarray
        Shape (1, n_features) — the encoded feature vector for this event.
    feature_names : list[str]
        Ordered feature names matching feature_vector columns.

    Returns
    -------
    dict with keys:
        shap_values            : dict[feature_name -> shap_value]
        anomalous_features     : list[dict]  — features with negative SHAP, sorted most→least negative
        top_feature            : str         — feature name with most negative SHAP
        top_shap_value         : float       — SHAP value of top feature (<0)
        attribution_confidence : float       — fraction of anomaly explained by top feature (0–1)
        expected_value         : float       — model baseline score
        is_uncertain           : bool        — True if attribution_confidence < MIN_CONFIDENCE
    """
    from config import MIN_ATTRIBUTION_CONFIDENCE

    explainer = _get_explainer(model)

    # Compute SHAP values — shape (1, n_features) for single sample
    raw_shap = explainer.shap_values(feature_vector)

    # Handle both (n_features,) and (1, n_features) shapes
    if isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 2:
        shap_row = raw_shap[0]
    else:
        shap_row = np.array(raw_shap).flatten()

    expected_value = float(
        explainer.expected_value[0]
        if hasattr(explainer.expected_value, "__len__")
        else explainer.expected_value
    )

    # Build per-feature SHAP dict
    shap_values = {
        name: float(val)
        for name, val in zip(feature_names, shap_row)
    }

    # Identify anomalous features (negative SHAP only)
    anomalous_features = sorted(
        [
            {"feature": name, "shap_value": val}
            for name, val in shap_values.items()
            if val < 0
        ],
        key=lambda x: x["shap_value"],  # most negative first
    )

    if not anomalous_features:
        # Edge case: all SHAP values positive — still flag but mark uncertain
        logger.warning("No negative SHAP values found for anomalous event — marking uncertain")
        top_feature   = feature_names[int(np.argmin(shap_row))]
        top_shap_val  = float(np.min(shap_row))
        confidence    = 0.0
    else:
        top_feature  = anomalous_features[0]["feature"]
        top_shap_val = anomalous_features[0]["shap_value"]

        total_negative = sum(abs(f["shap_value"]) for f in anomalous_features)
        confidence = abs(top_shap_val) / total_negative if total_negative > 0 else 0.0

    is_uncertain = confidence < MIN_ATTRIBUTION_CONFIDENCE

    logger.info(
        "explain: top_feature=%s top_shap=%.4f confidence=%.3f uncertain=%s",
        top_feature, top_shap_val, confidence, is_uncertain,
    )

    return {
        "shap_values":            shap_values,
        "anomalous_features":     anomalous_features,
        "top_feature":            top_feature,
        "top_shap_value":         top_shap_val,
        "attribution_confidence": round(confidence, 4),
        "expected_value":         expected_value,
        "is_uncertain":           is_uncertain,
    }
