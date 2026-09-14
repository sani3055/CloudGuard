"""
threat_classifier.py
====================
Maps XAI evidence (SHAP attributions) and raw event context to a named,
defensible threat category with MITRE ATT&CK mapping.

Design principles:
  - Rules are evaluated in PRIORITY ORDER (privilege escalation > defense evasion > ...)
  - Each rule requires both XAI evidence AND event-level context to fire
  - Attribution confidence < MIN_ATTRIBUTION_CONFIDENCE always yields "Uncertain"
  - All categories include a MITRE ATT&CK technique reference for research validity

Risk Score Formula (for anomalies):
  base_score  = clamp((-anomaly_score + 0.05) * 300, 0, 60)
  bonus       = severity_bonus * clamp(attribution_confidence, 0, 1)
  risk_score  = clamp(base_score + bonus, 0, 100)
  severity_bonus: Critical=40, High=25, Medium=10, Low=0
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat category definitions
# ---------------------------------------------------------------------------

THREAT_CATEGORIES = {
    "PRIVILEGE_ESCALATION": {
        "label":           "Privilege Escalation",
        "mitre_technique": "T1078 / T1098",
        "mitre_name":      "Valid Accounts / Account Manipulation",
        "description":     "IAM permissions expanded or access keys created outside normal patterns.",
        "severity":        "Critical",
    },
    "DEFENSE_EVASION": {
        "label":           "Defense Evasion",
        "mitre_technique": "T1562",
        "mitre_name":      "Impair Defenses",
        "description":     "Audit trail or security controls disabled or deleted.",
        "severity":        "Critical",
    },
    "GEOGRAPHIC_ANOMALY": {
        "label":           "Geographic Anomaly",
        "mitre_technique": "T1078.004",
        "mitre_name":      "Cloud Accounts — Unusual Region",
        "description":     "API call originated from an unexpected AWS region.",
        "severity":        "High",
    },
    "TEMPORAL_ANOMALY": {
        "label":           "Temporal Anomaly",
        "mitre_technique": "T1078",
        "mitre_name":      "Valid Accounts — Off-Hours Activity",
        "description":     "Activity detected outside normal business hours (UTC 06:00–22:00).",
        "severity":        "High",
    },
    "RESOURCE_EXFILTRATION": {
        "label":           "Resource Access Anomaly",
        "mitre_technique": "T1530",
        "mitre_name":      "Data from Cloud Storage Object",
        "description":     "Unusual data access pattern — possible exfiltration attempt.",
        "severity":        "High",
    },
    "CREDENTIAL_ANOMALY": {
        "label":           "Credential / Root Account Anomaly",
        "mitre_technique": "T1078.004",
        "mitre_name":      "Cloud Accounts — Root Credential Usage",
        "description":     "Root account used for API activity. AWS best practice: never use root for API calls.",
        "severity":        "Critical",
    },
    "UNCERTAIN": {
        "label":           "Uncertain — Multi-Feature Anomaly",
        "mitre_technique": "N/A",
        "mitre_name":      "N/A",
        "description":     "Anomaly detected but attribution confidence too low for automated classification.",
        "severity":        "Medium",
    },
}

# Business hours (UTC). Outside this range → temporal anomaly candidate.
BUSINESS_HOURS_START = 6   # 06:00 UTC
BUSINESS_HOURS_END   = 22  # 22:00 UTC

# Severity → category bonus points (added on top of IF base score)
_SEVERITY_BONUS: dict[str, int] = {
    "Critical": 40,
    "High":     25,
    "Medium":   10,
    "Low":       0,
    "Unknown":   5,
}


# ---------------------------------------------------------------------------
# Risk Score — public API
# ---------------------------------------------------------------------------

def compute_risk_score(
    anomaly_score: float,
    severity: str,
    attribution_confidence: float,
) -> int:
    """
    Convert IsolationForest decision_function output to a 0–100 integer risk score.

    Formula
    -------
    base_score  = clamp((-anomaly_score + 0.05) * 300, 0, 60)
                  Practical IF range: [-0.20, +0.25]. Maps [-0.20, 0.0] → [0, 60].
    bonus       = severity_bonus * clamp(attribution_confidence, 0, 1)
    risk_score  = clamp(base_score + bonus, 0, 100)

    Interview rationale
    -------------------
    - The base score captures raw anomaly depth (how deep in the isolation tree).
    - The bonus reflects the qualitative severity assigned by the rule engine.
    - Confidence-weighting the bonus prevents noisy SHAP attributions from
      artificially inflating scores when the explanation is uncertain.

    Typical ranges:
      Critical, high confidence, very anomalous → 85–100
      High, medium confidence, moderate anomaly → 45–65
      Medium (UNCERTAIN), low confidence       → 15–30
      Normal event                              → 0–15 (via compute_risk_score_normal)
    """
    base  = max(0.0, min(60.0, (-anomaly_score + 0.05) * 300.0))
    bonus = _SEVERITY_BONUS.get(severity, 5) * max(0.0, min(1.0, attribution_confidence))
    return max(0, min(100, int(round(base + bonus))))


def compute_risk_score_normal(anomaly_score: float) -> int:
    """
    Compute a small risk score for non-anomalous events.

    Normal IF scores are typically +0.05 to +0.25.
    We map them to 0–15 so the dashboard shows a baseline risk floor.
    """
    risk = int(round(max(0.0, min(15.0, (-anomaly_score + 0.05) * 60.0))))
    return max(0, risk)


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

def classify_threat(
    xai_result: dict[str, Any],
    raw_features: dict[str, Any],
    anomaly_score: float = 0.0,
) -> dict[str, Any]:
    """
    Classify the threat category for a detected anomaly.

    Parameters
    ----------
    xai_result    : dict — output of xai_explainer.explain()
    raw_features  : dict — output of feature_contract.extract_features()
    anomaly_score : float — IF decision_function score (used for risk_score calc)

    Returns
    -------
    dict with keys:
        threat_category    : str  — category key (e.g. "PRIVILEGE_ESCALATION")
        label              : str  — human-readable label
        mitre_technique    : str
        mitre_name         : str
        description        : str
        severity           : str  — Critical / High / Medium / Low
        confidence_level   : str  — High / Medium / Low
        rationale          : str  — why this category was chosen
        enforcement_eligible: bool — False for uncertain/root/low-confidence
        risk_score         : int  — 0–100 composite risk score
    """
    # Uncertain gate — fires before all other rules
    if xai_result["is_uncertain"]:
        return _build_result(
            "UNCERTAIN",
            confidence_level="Low",
            rationale=(
                f"Attribution confidence {xai_result['attribution_confidence']:.2f} "
                f"is below threshold. Top anomalous feature: {xai_result['top_feature']}."
            ),
            enforcement_eligible=False,
            anomaly_score=anomaly_score,
            attribution_confidence=xai_result["attribution_confidence"],
        )

    top_feature  = xai_result["top_feature"]
    top_shap     = xai_result["top_shap_value"]
    event_name   = raw_features.get("eventName", "")
    user_type    = raw_features.get("userIdentitytype", "")
    hour         = raw_features.get("hour", -1)
    confidence   = xai_result["attribution_confidence"]
    conf_level   = _confidence_level(confidence)

    # ---------- Priority 1: Credential / Root anomaly ----------
    # Rule: top feature is userIdentitytype AND user is Root
    # Justification: Root credential usage is unconditionally anomalous per AWS best practices
    if top_feature == "userIdentitytype" and user_type == "Root":
        return _build_result(
            "CREDENTIAL_ANOMALY",
            confidence_level=conf_level,
            rationale=(
                f"Root account used for API call '{event_name}'. "
                f"userIdentitytype is the primary anomalous feature (SHAP={top_shap:.4f})."
            ),
            enforcement_eligible=False,  # Cannot attach inline policy to root
            anomaly_score=anomaly_score,
            attribution_confidence=confidence,
        )

    # ---------- Priority 2: Privilege Escalation ----------
    # Rule: top feature is eventName AND event is a known privilege-escalation API
    from feature_contract import PRIVILEGE_ESCALATION_EVENTS
    if top_feature == "eventName" and event_name in PRIVILEGE_ESCALATION_EVENTS:
        return _build_result(
            "PRIVILEGE_ESCALATION",
            confidence_level=conf_level,
            rationale=(
                f"'{event_name}' is a known privilege escalation API. "
                f"eventName is the primary anomalous feature (SHAP={top_shap:.4f})."
            ),
            enforcement_eligible=True,
            anomaly_score=anomaly_score,
            attribution_confidence=confidence,
        )

    # ---------- Priority 3: Defense Evasion ----------
    from feature_contract import DEFENSE_EVASION_EVENTS
    if top_feature == "eventName" and event_name in DEFENSE_EVASION_EVENTS:
        return _build_result(
            "DEFENSE_EVASION",
            confidence_level=conf_level,
            rationale=(
                f"'{event_name}' is a known defense evasion API (MITRE T1562). "
                f"eventName is the primary anomalous feature (SHAP={top_shap:.4f})."
            ),
            enforcement_eligible=True,
            anomaly_score=anomaly_score,
            attribution_confidence=confidence,
        )

    # ---------- Priority 4: Geographic Anomaly ----------
    if top_feature == "awsRegion":
        return _build_result(
            "GEOGRAPHIC_ANOMALY",
            confidence_level=conf_level,
            rationale=(
                f"AWS region '{raw_features.get('awsRegion')}' is anomalous relative to this "
                f"entity's typical activity. awsRegion is the primary anomalous feature "
                f"(SHAP={top_shap:.4f})."
            ),
            enforcement_eligible=True,
            anomaly_score=anomaly_score,
            attribution_confidence=confidence,
        )

    # ---------- Priority 5: Temporal Anomaly ----------
    if top_feature == "hour" and (hour < BUSINESS_HOURS_START or hour > BUSINESS_HOURS_END):
        return _build_result(
            "TEMPORAL_ANOMALY",
            confidence_level=conf_level,
            rationale=(
                f"Activity at hour {hour:02d}:xx UTC is outside business hours "
                f"({BUSINESS_HOURS_START:02d}:00–{BUSINESS_HOURS_END:02d}:00 UTC). "
                f"hour is the primary anomalous feature (SHAP={top_shap:.4f})."
            ),
            enforcement_eligible=True,
            anomaly_score=anomaly_score,
            attribution_confidence=confidence,
        )

    # ---------- Priority 6: Resource Exfiltration ----------
    from feature_contract import RESOURCE_EXFILTRATION_EVENTS
    if top_feature == "eventName" and event_name in RESOURCE_EXFILTRATION_EVENTS:
        return _build_result(
            "RESOURCE_EXFILTRATION",
            confidence_level=conf_level,
            rationale=(
                f"'{event_name}' is a data-access API that is anomalous in this context. "
                f"eventName is the primary anomalous feature (SHAP={top_shap:.4f})."
            ),
            enforcement_eligible=True,
            anomaly_score=anomaly_score,
            attribution_confidence=confidence,
        )

    # ---------- Fallback: Uncertain (rules exhausted) ----------
    return _build_result(
        "UNCERTAIN",
        confidence_level="Low",
        rationale=(
            f"No specific rule matched. Top anomalous feature: {top_feature} "
            f"(SHAP={top_shap:.4f}), event='{event_name}', hour={hour}."
        ),
        enforcement_eligible=False,
        anomaly_score=anomaly_score,
        attribution_confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_result(
    category: str,
    confidence_level: str,
    rationale: str,
    enforcement_eligible: bool,
    anomaly_score: float = 0.0,
    attribution_confidence: float = 0.0,
) -> dict[str, Any]:
    meta     = THREAT_CATEGORIES[category]
    severity = meta["severity"]
    risk     = compute_risk_score(anomaly_score, severity, attribution_confidence)
    result   = {
        "threat_category":      category,
        "label":                meta["label"],
        "mitre_technique":      meta["mitre_technique"],
        "mitre_name":           meta["mitre_name"],
        "description":          meta["description"],
        "severity":             severity,
        "confidence_level":     confidence_level,
        "rationale":            rationale,
        "enforcement_eligible": enforcement_eligible,
        "risk_score":           risk,
    }
    logger.info(
        "classify_threat -> %s (conf=%s enforce=%s risk=%d)",
        category, confidence_level, enforcement_eligible, risk,
    )
    return result


def _confidence_level(confidence: float) -> str:
    if confidence >= 0.60:
        return "High"
    if confidence >= 0.40:
        return "Medium"
    return "Low"
