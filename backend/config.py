"""
config.py
=========
Central configuration for the CloudGuard Lambda pipeline.

All safety gates, thresholds, and environment toggles live here.
Lambda reads these at cold-start. Override via environment variables for
different deployment environments (dev / staging / prod).
"""

import os

# ---------------------------------------------------------------------------
# Safety Modes — MUST remain True in development/demo
# ---------------------------------------------------------------------------

# When True:  policy is generated and validated but NEVER attached to IAM
# When False: enforcement is live — requires human approval token in DynamoDB
SIMULATION_MODE: bool = os.environ.get("SIMULATION_MODE", "true").lower() == "true"

# When True:  actual iam.put_user_policy() is called after human approval
# Only meaningful when SIMULATION_MODE is False
ENFORCE_MODE: bool = os.environ.get("ENFORCE_MODE", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Anomaly Score Threshold
# ---------------------------------------------------------------------------

# IsolationForest decision_function: negative score = anomalous
# We only trigger the XAI/IAM pipeline when score is below this threshold.
# -0.02 is a conservative threshold; adjust based on Phase 9 evaluation.
ANOMALY_SCORE_THRESHOLD: float = float(os.environ.get("ANOMALY_SCORE_THRESHOLD", "-0.02"))

# Minimum SHAP attribution confidence to attempt automated threat classification.
# If top-feature attribution < this fraction of total anomaly, classify as "Uncertain".
MIN_ATTRIBUTION_CONFIDENCE: float = float(
    os.environ.get("MIN_ATTRIBUTION_CONFIDENCE", "0.30")
)

# ---------------------------------------------------------------------------
# Protected IAM Principals
# ---------------------------------------------------------------------------
# These ARNs will NEVER have a remediation policy attached — alert only.
# Populate from environment variable as a comma-separated list.
# Example: "arn:aws:iam::123456789012:root,arn:aws:iam::123456789012:user/admin"

_protected_env: str = os.environ.get("PROTECTED_PRINCIPALS", "")
PROTECTED_PRINCIPALS: frozenset[str] = frozenset(
    p.strip() for p in _protected_env.split(",") if p.strip()
) | frozenset({
    # Always protect root — root cannot have inline policies anyway
    # but we block alerting pipeline from generating enforcement rec
    "root",
})

# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------
DYNAMODB_TABLE: str = os.environ.get("DYNAMODB_TABLE_NAME", os.environ.get("DYNAMODB_TABLE", "CloudGuard-ThreatEvents"))
DYNAMODB_REGION: str = os.environ.get("DYNAMODB_REGION", "ap-south-1")

# ---------------------------------------------------------------------------
# SNS
# ---------------------------------------------------------------------------
SNS_TOPIC_ARN: str = os.environ.get("SNS_TOPIC_ARN", "")
SNS_REGION: str = os.environ.get("SNS_REGION", "ap-south-1")

# ---------------------------------------------------------------------------
# IAM Access Analyzer
# ---------------------------------------------------------------------------
ACCESS_ANALYZER_REGION: str = os.environ.get("ACCESS_ANALYZER_REGION", "us-east-1")

# Finding types that BLOCK enforcement (policy must not proceed)
BLOCKING_FINDING_TYPES: frozenset[str] = frozenset(["ERROR", "SECURITY_WARNING"])

# Finding types that ALLOW with approval (WARNING: security concern, but not fatal)
ALLOWED_WITH_WARNING_TYPES: frozenset[str] = frozenset(["WARNING"])

# Finding types that are purely informational — proceed without approval
SUGGESTION_TYPES: frozenset[str] = frozenset(["SUGGESTION"])

# ---------------------------------------------------------------------------
# ML Artefact Paths (inside the Lambda container /var/task/)
# ---------------------------------------------------------------------------
import pathlib

_BASE = pathlib.Path(__file__).parent
_ml_dir = (_BASE / "ml") if (_BASE / "ml").exists() else (_BASE.parent / "ml")

MODEL_PATH:   pathlib.Path = _ml_dir / "model.pkl"
ENCODER_PATH: pathlib.Path = _ml_dir / "encoder.pkl"

# ---------------------------------------------------------------------------
# Logging / Audit
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
