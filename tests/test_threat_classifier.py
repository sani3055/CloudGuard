"""
test_threat_classifier.py
=========================
Unit tests for threat_classifier.py:
  - compute_risk_score()          — formula boundary tests
  - compute_risk_score_normal()   — normal event scoring
  - classify_threat()             — all 6 categories + UNCERTAIN gate

No AWS credentials required.
Run from project root:
  python -m pytest tests/test_threat_classifier.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from threat_classifier import (
    classify_threat,
    compute_risk_score,
    compute_risk_score_normal,
    THREAT_CATEGORIES,
)
from feature_contract import (
    PRIVILEGE_ESCALATION_EVENTS,
    DEFENSE_EVASION_EVENTS,
    RESOURCE_EXFILTRATION_EVENTS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _xai(
    top_feature: str,
    top_shap: float = -0.25,
    confidence: float = 0.75,
    is_uncertain: bool = False,
) -> dict:
    """Build a minimal xai_result dict."""
    return {
        "is_uncertain":          is_uncertain,
        "top_feature":           top_feature,
        "top_shap_value":        top_shap,
        "attribution_confidence": confidence,
        "shap_values":           {},
    }


def _features(
    event_name: str = "ListBuckets",
    user_type: str = "IAMUser",
    hour: int = 10,
    region: str = "us-east-1",
    is_root: int = 0,
) -> dict:
    """Build a minimal feature dict."""
    return {
        "eventName":          event_name,
        "userIdentitytype":   user_type,
        "hour":               hour,
        "awsRegion":          region,
        "isRoot":             is_root,
    }


# ---------------------------------------------------------------------------
# compute_risk_score() — boundary & formula tests
# ---------------------------------------------------------------------------

class TestComputeRiskScore:

    def test_very_anomalous_critical_high_confidence_approaches_100(self):
        """Very anomalous IF score + Critical + high confidence → near 100."""
        score = compute_risk_score(-0.20, "Critical", 1.0)
        assert score >= 85, f"Expected >=85, got {score}"
        assert score <= 100

    def test_clamped_to_100_max(self):
        """Extreme inputs must not exceed 100."""
        score = compute_risk_score(-1.0, "Critical", 1.0)
        assert score == 100

    def test_clamped_to_0_min(self):
        """Very positive IF score → 0."""
        score = compute_risk_score(0.5, "Low", 0.0)
        assert score == 0

    def test_severity_ordering_critical_gt_high_gt_medium_gt_low(self):
        """Severity bonus must be monotonically decreasing."""
        base_anomaly = -0.05
        base_conf    = 0.8
        s_crit   = compute_risk_score(base_anomaly, "Critical", base_conf)
        s_high   = compute_risk_score(base_anomaly, "High",     base_conf)
        s_medium = compute_risk_score(base_anomaly, "Medium",   base_conf)
        s_low    = compute_risk_score(base_anomaly, "Low",      base_conf)
        assert s_crit > s_high > s_medium > s_low, (
            f"Expected Critical > High > Medium > Low, got "
            f"{s_crit} {s_high} {s_medium} {s_low}"
        )

    def test_zero_confidence_yields_only_base_score(self):
        """When confidence=0, bonus contribution is 0 regardless of severity."""
        score_critical = compute_risk_score(-0.05, "Critical", 0.0)
        score_low      = compute_risk_score(-0.05, "Low",      0.0)
        assert score_critical == score_low, (
            "With confidence=0, Critical and Low should have the same score"
        )

    def test_normal_event_positive_score_maps_near_zero(self):
        """Positive IF scores (normal events) should produce a low risk score."""
        score = compute_risk_score(0.15, "Low", 0.0)
        assert score == 0

    def test_return_type_is_int(self):
        assert isinstance(compute_risk_score(-0.05, "High", 0.7), int)

    def test_unknown_severity_does_not_crash(self):
        score = compute_risk_score(-0.05, "Unknown", 0.5)
        assert 0 <= score <= 100


class TestComputeRiskScoreNormal:

    def test_positive_score_maps_to_zero(self):
        """Strongly normal events (high positive IF score) → 0."""
        assert compute_risk_score_normal(0.25) == 0

    def test_near_threshold_maps_small_positive(self):
        """Score just above zero → small positive risk."""
        score = compute_risk_score_normal(0.0)
        assert 0 <= score <= 15

    def test_clamped_to_15_max(self):
        score = compute_risk_score_normal(-0.5)
        assert score <= 15

    def test_return_type_is_int(self):
        assert isinstance(compute_risk_score_normal(0.1), int)


# ---------------------------------------------------------------------------
# classify_threat() — all 6 categories
# ---------------------------------------------------------------------------

class TestClassifyThreat:

    # ── Uncertain gate ──────────────────────────────────────────────────

    def test_uncertain_gate_fires_when_is_uncertain_true(self):
        result = classify_threat(
            _xai("eventName", is_uncertain=True),
            _features("AttachUserPolicy"),
            anomaly_score=-0.05,
        )
        assert result["threat_category"] == "UNCERTAIN"
        assert result["enforcement_eligible"] is False

    def test_uncertain_gate_includes_risk_score(self):
        result = classify_threat(
            _xai("eventName", is_uncertain=True, confidence=0.15),
            _features(),
            anomaly_score=-0.03,
        )
        assert "risk_score" in result
        assert isinstance(result["risk_score"], int)
        assert 0 <= result["risk_score"] <= 100

    # ── Priority 1: Credential / Root ──────────────────────────────────

    def test_root_account_classified_as_credential_anomaly(self):
        result = classify_threat(
            _xai("userIdentitytype", confidence=0.8),
            _features(event_name="ListBuckets", user_type="Root", is_root=1),
            anomaly_score=-0.10,
        )
        assert result["threat_category"] == "CREDENTIAL_ANOMALY"
        assert result["severity"] == "Critical"
        assert result["enforcement_eligible"] is False  # root can't have inline policy

    def test_root_anomaly_has_high_risk_score(self):
        result = classify_threat(
            _xai("userIdentitytype", confidence=0.9),
            _features(user_type="Root", is_root=1),
            anomaly_score=-0.12,
        )
        assert result["risk_score"] > 50

    # ── Priority 2: Privilege Escalation ───────────────────────────────

    def test_privilege_escalation_classified_correctly(self):
        priv_event = next(iter(PRIVILEGE_ESCALATION_EVENTS))
        result = classify_threat(
            _xai("eventName", confidence=0.8),
            _features(event_name=priv_event),
            anomaly_score=-0.10,
        )
        assert result["threat_category"] == "PRIVILEGE_ESCALATION"
        assert result["severity"] == "Critical"
        assert result["enforcement_eligible"] is True

    def test_privilege_escalation_attach_user_policy(self):
        result = classify_threat(
            _xai("eventName", confidence=0.85),
            _features(event_name="AttachUserPolicy"),
            anomaly_score=-0.08,
        )
        assert result["threat_category"] == "PRIVILEGE_ESCALATION"

    # ── Priority 3: Defense Evasion ─────────────────────────────────────

    def test_defense_evasion_delete_trail(self):
        result = classify_threat(
            _xai("eventName", confidence=0.7),
            _features(event_name="DeleteTrail"),
            anomaly_score=-0.12,
        )
        assert result["threat_category"] == "DEFENSE_EVASION"
        assert result["severity"] == "Critical"
        assert result["enforcement_eligible"] is True

    def test_defense_evasion_mitre_technique_T1562(self):
        result = classify_threat(
            _xai("eventName", confidence=0.7),
            _features(event_name="DeleteTrail"),
            anomaly_score=-0.12,
        )
        assert "T1562" in result["mitre_technique"]

    # ── Priority 4: Geographic Anomaly ─────────────────────────────────

    def test_geographic_anomaly_when_top_feature_is_region(self):
        result = classify_threat(
            _xai("awsRegion", confidence=0.65),
            _features(region="ap-southeast-99"),
            anomaly_score=-0.07,
        )
        assert result["threat_category"] == "GEOGRAPHIC_ANOMALY"
        assert result["severity"] == "High"
        assert result["enforcement_eligible"] is True

    # ── Priority 5: Temporal Anomaly ────────────────────────────────────

    def test_temporal_anomaly_off_hours(self):
        result = classify_threat(
            _xai("hour", confidence=0.6),
            _features(hour=3),
            anomaly_score=-0.06,
        )
        assert result["threat_category"] == "TEMPORAL_ANOMALY"
        assert result["severity"] == "High"

    def test_temporal_anomaly_at_business_hours_does_not_fire(self):
        """If hour is within business hours and top_feature is 'hour', fallback UNCERTAIN."""
        result = classify_threat(
            _xai("hour", confidence=0.6),
            _features(hour=12),   # noon UTC — business hours
            anomaly_score=-0.06,
        )
        # hour at 12 is inside 06–22, so temporal rule won't fire → fallback UNCERTAIN
        assert result["threat_category"] == "UNCERTAIN"

    # ── Priority 6: Resource Exfiltration ───────────────────────────────

    def test_resource_exfiltration_get_object(self):
        exfil_event = next(iter(RESOURCE_EXFILTRATION_EVENTS))
        result = classify_threat(
            _xai("eventName", confidence=0.55),
            _features(event_name=exfil_event),
            anomaly_score=-0.07,
        )
        assert result["threat_category"] == "RESOURCE_EXFILTRATION"
        assert result["severity"] == "High"

    # ── Common output contract ───────────────────────────────────────────

    @pytest.mark.parametrize("category", list(THREAT_CATEGORIES.keys()))
    def test_all_required_keys_present(self, category):
        """Every category result must include the standard output contract."""
        required = {
            "threat_category", "label", "mitre_technique", "mitre_name",
            "description", "severity", "confidence_level", "rationale",
            "enforcement_eligible", "risk_score",
        }
        # Build appropriate inputs for each category
        if category == "CREDENTIAL_ANOMALY":
            xai = _xai("userIdentitytype", confidence=0.8)
            feats = _features(user_type="Root")
        elif category == "PRIVILEGE_ESCALATION":
            xai = _xai("eventName", confidence=0.8)
            feats = _features(event_name="AttachUserPolicy")
        elif category == "DEFENSE_EVASION":
            xai = _xai("eventName", confidence=0.8)
            feats = _features(event_name="DeleteTrail")
        elif category == "GEOGRAPHIC_ANOMALY":
            xai = _xai("awsRegion", confidence=0.8)
            feats = _features()
        elif category == "TEMPORAL_ANOMALY":
            xai = _xai("hour", confidence=0.8)
            feats = _features(hour=3)
        elif category == "RESOURCE_EXFILTRATION":
            xai = _xai("eventName", confidence=0.8)
            feats = _features(event_name="GetObject")
        else:  # UNCERTAIN
            xai = _xai("eventName", is_uncertain=True, confidence=0.1)
            feats = _features()

        result = classify_threat(xai, feats, anomaly_score=-0.08)
        # UNCERTAIN gate might fire before reaching the specific category for some
        # inputs — just check that ALL keys are present
        assert required <= result.keys(), f"Missing keys: {required - result.keys()}"

    def test_risk_score_always_in_range(self):
        """risk_score must always be 0–100 regardless of inputs."""
        xai = _xai("eventName", confidence=0.8)
        feats = _features(event_name="AttachUserPolicy")
        for score in [-0.5, -0.2, -0.05, 0.0, 0.2]:
            result = classify_threat(xai, feats, anomaly_score=score)
            assert 0 <= result["risk_score"] <= 100, (
                f"risk_score out of range for anomaly_score={score}: {result['risk_score']}"
            )

    def test_anomalous_events_score_higher_than_normal(self):
        """A highly anomalous Critical event should score higher than a borderline one."""
        xai = _xai("eventName", confidence=0.85)
        feats = _features(event_name="AttachUserPolicy")

        high_risk   = classify_threat(xai, feats, anomaly_score=-0.18)
        medium_risk = classify_threat(xai, feats, anomaly_score=-0.03)
        assert high_risk["risk_score"] > medium_risk["risk_score"]
