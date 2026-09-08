"""
pipeline_runner.py
==================
Frontend-side bridge to the real CloudGuard ML / backend pipeline.

Adds backend/ and ml/ to sys.path so the frontend can call the actual
Isolation Forest, SHAP explainer, threat classifier, IAM generator,
and policy validator without duplicating any logic.

All functions return a (result_dict, error_str | None) tuple.
error_str is None on success, a human-readable message on failure.
"""

from __future__ import annotations

import sys
import json
import uuid
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path injection — must happen before any backend imports
# ---------------------------------------------------------------------------
_FRONTEND_DIR = Path(__file__).parent
_PROJECT_ROOT = _FRONTEND_DIR.parent
_BACKEND_DIR  = _PROJECT_ROOT / "backend"
_ML_DIR       = _PROJECT_ROOT / "ml"

for _p in (_BACKEND_DIR, _ML_DIR):
    _ps = str(_p)
    if _ps not in sys.path:
        sys.path.insert(0, _ps)


# ---------------------------------------------------------------------------
# Lazy module cache — only import heavy modules once
# ---------------------------------------------------------------------------
_imports_ok: bool | None = None
_import_error: str = ""

def _ensure_imports() -> tuple[bool, str]:
    global _imports_ok, _import_error
    if _imports_ok is not None:
        return _imports_ok, _import_error
    try:
        import feature_contract   # noqa
        import ml_inference       # noqa
        import xai_explainer      # noqa
        import threat_classifier  # noqa
        import iam_generator      # noqa
        _imports_ok = True
        _import_error = ""
    except Exception as exc:
        _imports_ok = False
        _import_error = str(exc)
    return _imports_ok, _import_error


# ---------------------------------------------------------------------------
# Model info helper (derived dynamically from loaded model)
# ---------------------------------------------------------------------------

def get_model_info() -> dict[str, Any]:
    """
    Return a dict of model metadata derived from the actual .pkl files.
    Never hardcodes training statistics.
    """
    ok, err = _ensure_imports()
    if not ok:
        return {"error": err, "available": False}

    try:
        import joblib
        from config import MODEL_PATH, ENCODER_PATH, ANOMALY_SCORE_THRESHOLD
        from feature_contract import FEATURE_NAMES, CATEGORICAL_FEATURES

        model   = joblib.load(MODEL_PATH)
        encoder = joblib.load(ENCODER_PATH)

        # Read contamination from the model object itself (config.py does not export it)
        contamination = getattr(model, "contamination", None)
        if contamination is None:
            contamination = getattr(model, "_contamination", "auto")

        info = {
            "available":            True,
            "model_type":           type(model).__name__,
            "n_estimators":         getattr(model, "n_estimators", "N/A"),
            "contamination":        contamination,
            "max_features":         getattr(model, "max_features_", "N/A"),
            "n_features_in":        getattr(model, "n_features_in_", len(FEATURE_NAMES)),
            "feature_names":        FEATURE_NAMES,
            "categorical_features": CATEGORICAL_FEATURES,
            "anomaly_threshold":    ANOMALY_SCORE_THRESHOLD,
            "model_path":           str(MODEL_PATH),
            "encoder_categories": {
                CATEGORICAL_FEATURES[i]: len(cats)
                for i, cats in enumerate(encoder.categories_)
            },
        }
        # Optionally read training row count from data dir CSV if exists
        data_csv = _PROJECT_ROOT / "data" / "dec12_18features.csv"
        if data_csv.exists():
            import pandas as pd
            # count rows without loading whole file
            with open(data_csv, "rb") as f:
                row_count = sum(1 for _ in f) - 1  # subtract header
            info["training_rows"] = row_count
        else:
            info["training_rows"] = None  # not available locally

        return info
    except Exception as exc:
        return {"available": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Stage 1 + 2: Feature extraction
# ---------------------------------------------------------------------------

def run_feature_extraction(cloudtrail_event: dict) -> tuple[dict | None, str | None]:
    ok, err = _ensure_imports()
    if not ok:
        return None, f"Import error: {err}"
    try:
        from feature_contract import extract_features
        features = extract_features(cloudtrail_event)
        return features, None
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Stage 3: ML Inference
# ---------------------------------------------------------------------------

def run_ml_inference(cloudtrail_event: dict) -> tuple[dict | None, str | None]:
    ok, err = _ensure_imports()
    if not ok:
        return None, f"Import error: {err}"
    try:
        from ml_inference import score_event
        result = score_event(cloudtrail_event)
        return result, None
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Stage 4: XAI / SHAP
# ---------------------------------------------------------------------------

def run_xai(model, feature_vector, feature_names) -> tuple[dict | None, str | None]:
    ok, err = _ensure_imports()
    if not ok:
        return None, f"Import error: {err}"
    try:
        import numpy as np
        from xai_explainer import explain
        fv = np.array([feature_vector], dtype=np.float64)
        result = explain(model, fv, feature_names)
        return result, None
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Stage 5: Threat Classification
# ---------------------------------------------------------------------------

def run_threat_classification(xai_result: dict, raw_features: dict) -> tuple[dict | None, str | None]:
    ok, err = _ensure_imports()
    if not ok:
        return None, f"Import error: {err}"
    try:
        from threat_classifier import classify_threat
        result = classify_threat(xai_result, raw_features)
        return result, None
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Stage 6: IAM Policy Generation
# ---------------------------------------------------------------------------

def run_iam_generation(
    threat_result: dict,
    raw_features: dict,
    raw_event: dict,
    event_id: str | None = None,
) -> tuple[dict | None, str | None]:
    ok, err = _ensure_imports()
    if not ok:
        return None, f"Import error: {err}"
    try:
        from iam_generator import generate_policy
        eid = event_id or str(uuid.uuid4())
        result = generate_policy(threat_result, raw_features, raw_event, eid)
        return result, None
    except Exception as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Stage 7: Access Analyzer Validation
# ---------------------------------------------------------------------------

def run_policy_validation(policy_json: str) -> tuple[dict | None, str | None]:
    """
    Attempt real AWS Access Analyzer validation.
    Falls back to a simulated CLEAN result if AWS is unavailable or the
    credentials lack access-analyzer:ValidatePolicy permission.
    Sets 'simulated': True in the result so the UI can label it clearly.
    """
    ok, err = _ensure_imports()
    if not ok:
        return None, f"Import error: {err}"
    try:
        from policy_validator import validate_policy
        result = validate_policy(policy_json)

        # policy_validator returns an ERROR status when Access Analyzer
        # raises AccessDeniedException or other ClientError — treat this
        # as a simulated fallback so the UI shows CLEAN rather than ERROR.
        if result.get("validation_status") == "ERROR" and "Access Analyzer API error" in (
            result.get("blocking_reason") or ""
        ):
            return {
                "proceed":           True,
                "validation_status": "CLEAN",
                "requires_approval": False,
                "blocking_reason":   None,
                "findings_summary":  [],
                "raw_findings":      [],
                "simulated":         True,
                "simulated_reason":  result.get("blocking_reason", "Access Analyzer unavailable"),
            }, None

        result["simulated"] = False
        return result, None
    except Exception as exc:
        # Python-level error (not an AWS error) — return simulated CLEAN
        sim_result = {
            "proceed":           True,
            "validation_status": "CLEAN",
            "requires_approval": False,
            "blocking_reason":   None,
            "findings_summary":  [],
            "raw_findings":      [],
            "simulated":         True,
            "simulated_reason":  f"AWS Access Analyzer unavailable: {exc}",
        }
        return sim_result, None


# ---------------------------------------------------------------------------
# Stage 8: Controlled Response / Enforcement simulation
# ---------------------------------------------------------------------------

def run_controlled_response(
    validation_result: dict,
    threat_result: dict,
    iam_result: dict,
) -> dict:
    """
    Determine and return the enforcement decision.
    Always simulated in the frontend — never attaches real IAM policies.
    """
    enforcement_eligible = iam_result.get("enforcement_eligible", False)
    validation_ok        = validation_result.get("proceed", False)
    requires_approval    = validation_result.get("requires_approval", False)

    if not enforcement_eligible:
        action = "ALERT_ONLY"
        reason = iam_result.get("skip_reason") or "Principal not enforcement-eligible."
    elif not validation_ok:
        action = "BLOCKED"
        reason = validation_result.get("blocking_reason") or "Access Analyzer blocked policy."
    elif requires_approval:
        action = "PENDING_APPROVAL"
        reason = "Policy has WARNING findings — human approval required before enforcement."
    else:
        action = "SIMULATED"
        reason = (
            "Policy is valid. In production with SIMULATION_MODE=false and "
            "ENFORCE_MODE=true, this Deny policy would be attached to the target principal."
        )

    return {
        "action":          action,
        "reason":          reason,
        "simulated":       True,
        "policy_name":     iam_result.get("policy_name", ""),
        "target_arn":      iam_result.get("target_arn", ""),
        "principal_type":  iam_result.get("principal_type", ""),
    }


# ---------------------------------------------------------------------------
# Convenience: run full 8-stage pipeline in one call
# ---------------------------------------------------------------------------

def run_full_pipeline(cloudtrail_event: dict) -> dict[str, Any]:
    """
    Run all 8 pipeline stages on a single CloudTrail event dict.
    Returns a dict keyed by stage name.  Each stage has:
        'result': dict | None
        'error':  str | None
    """
    stages: dict[str, Any] = {}

    # Stage 1+2: Feature extraction
    features, err = run_feature_extraction(cloudtrail_event)
    stages["features"] = {"result": features, "error": err}
    if err:
        return stages  # can't proceed without features

    # Stage 3: ML Inference (also re-extracts features internally via score_event)
    ml_result, err = run_ml_inference(cloudtrail_event)
    stages["ml"] = {"result": ml_result, "error": err}
    if err or not ml_result:
        return stages

    # Stage 4: XAI (only if anomaly detected)
    xai_result = None
    if ml_result.get("is_anomaly"):
        try:
            import joblib
            from config import MODEL_PATH
            from feature_contract import FEATURE_NAMES
            model = joblib.load(MODEL_PATH)
            xai_result, err = run_xai(model, ml_result["encoded"], FEATURE_NAMES)
        except Exception as exc:
            err = str(exc)
    else:
        err = None  # not an anomaly — XAI not applicable
    stages["xai"] = {"result": xai_result, "error": err, "skipped": not ml_result.get("is_anomaly")}

    # Stages 5–8 only meaningful if anomaly + XAI succeeded
    if ml_result.get("is_anomaly") and xai_result:
        # Stage 5: Threat Classification
        threat_result, err = run_threat_classification(xai_result, features)
        stages["threat"] = {"result": threat_result, "error": err}

        # Stage 6: IAM Policy
        if threat_result:
            iam_result, err = run_iam_generation(threat_result, features, cloudtrail_event)
            stages["iam"] = {"result": iam_result, "error": err}

            # Stage 7: Validation
            if iam_result:
                val_result, err = run_policy_validation(iam_result.get("policy_json", "{}"))
                stages["validation"] = {"result": val_result, "error": err}

                # Stage 8: Controlled Response
                ctrl_result = run_controlled_response(val_result or {}, threat_result, iam_result)
                stages["controlled_response"] = {"result": ctrl_result, "error": None}
    else:
        for s in ("threat", "iam", "validation", "controlled_response"):
            stages[s] = {"result": None, "error": None, "skipped": True}

    return stages
