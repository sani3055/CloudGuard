import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _policy_result(enforcement_eligible=True, target_arn="arn:aws:iam::123:user/alice"):
    return {
        "policy_name":          "CG-TestPolicy-abc123",
        "policy_json":          '{"Version":"2012-10-17","Statement":[]}',
        "target_arn":           target_arn,
        "principal_type":       "IAMUser",
        "enforcement_eligible": enforcement_eligible,
        "skip_reason":          None,
    }


def _validation_result(proceed=True, requires_approval=False, validation_status="CLEAN"):
    return {
        "validation_status": validation_status,
        "proceed":           proceed,
        "requires_approval": requires_approval,
        "findings_summary":  [],
    }


def _score_result(anomaly_score=-0.10):
    return {
        "features": {
            "eventName":        "AttachUserPolicy",
            "awsRegion":        "us-east-1",
            "userIdentitytype": "IAMUser",
            "isRoot":           0,
            "hour":             10,
        },
        "anomaly_score": anomaly_score,
        "is_anomaly":    True,
        "prediction":    -1,
        "encoded":       [0.0, 10.0, 1.0, 0.0, 0.0],
    }


def _xai_result():
    return {
        "top_feature":            "eventName",
        "top_shap_value":         -0.30,
        "attribution_confidence":  0.80,
        "is_uncertain":           False,
        "shap_values":            {},
    }


def _threat_result(risk_score=72, severity="Critical"):
    return {
        "threat_category":      "PRIVILEGE_ESCALATION",
        "label":                "Privilege Escalation",
        "mitre_technique":      "T1078 / T1098",
        "mitre_name":           "Valid Accounts",
        "description":          "IAM permissions expanded.",
        "severity":             severity,
        "confidence_level":     "High",
        "rationale":            "AttachUserPolicy is a known privilege escalation API.",
        "enforcement_eligible": True,
        "risk_score":           risk_score,
    }


def _raw_event():
    return {"detail": {
        "eventTime":     "2026-01-01T10:00:00Z",
        "eventSource":   "iam.amazonaws.com",
        "sourceIPAddress": "1.2.3.4",
    }}


# ---------------------------------------------------------------------------
# _determine_status() — pure function, no AWS calls
# ---------------------------------------------------------------------------

class TestDetermineStatus:

    def _call(self, policy, validation, simulation, enforce):
        import remediation as rem
        orig_sim, orig_enf = rem.SIMULATION_MODE, rem.ENFORCE_MODE
        rem.SIMULATION_MODE, rem.ENFORCE_MODE = simulation, enforce
        try:
            return rem._determine_status(policy, validation)
        finally:
            rem.SIMULATION_MODE, rem.ENFORCE_MODE = orig_sim, orig_enf

    def test_simulation_mode_always_returns_simulated(self):
        status = self._call(
            _policy_result(enforcement_eligible=True),
            _validation_result(proceed=True, requires_approval=False),
            simulation=True, enforce=True,
        )
        assert status == "SIMULATED"

    def test_blocked_when_validation_does_not_proceed(self):
        status = self._call(
            _policy_result(enforcement_eligible=True),
            _validation_result(proceed=False, validation_status="BLOCKED"),
            simulation=False, enforce=False,
        )
        assert status == "BLOCKED"

    def test_pending_approval_when_requires_approval(self):
        status = self._call(
            _policy_result(enforcement_eligible=True),
            _validation_result(proceed=True, requires_approval=True),
            simulation=False, enforce=False,
        )
        assert status == "PENDING_APPROVAL"

    def test_simulated_when_enforcement_not_eligible(self):
        status = self._call(
            _policy_result(enforcement_eligible=False),
            _validation_result(proceed=True, requires_approval=False),
            simulation=False, enforce=False,
        )
        assert status == "SIMULATED"

    def test_approved_for_enforcement_when_all_clear(self):
        status = self._call(
            _policy_result(enforcement_eligible=True),
            _validation_result(proceed=True, requires_approval=False),
            simulation=False, enforce=True,
        )
        assert status == "APPROVED_FOR_ENFORCEMENT"


# ---------------------------------------------------------------------------
# _enforce_policy() — must not make real IAM calls
# ---------------------------------------------------------------------------

class TestEnforcePolicy:

    def test_simulation_mode_blocks_iam_call(self):
        import remediation as rem
        orig_sim = rem.SIMULATION_MODE
        rem.SIMULATION_MODE = True
        try:
            with patch("boto3.client") as mock_boto:
                result = rem._enforce_policy(_policy_result(), "test-event-id")
            assert result is False
            mock_boto.assert_not_called()
        finally:
            rem.SIMULATION_MODE = orig_sim

    def test_enforcement_not_eligible_blocks_iam_call(self):
        import remediation as rem
        orig_sim = rem.SIMULATION_MODE
        rem.SIMULATION_MODE = False
        try:
            with patch("boto3.client") as mock_boto:
                result = rem._enforce_policy(
                    _policy_result(enforcement_eligible=False), "test-event-id"
                )
            assert result is False
            mock_boto.assert_not_called()
        finally:
            rem.SIMULATION_MODE = orig_sim


# ---------------------------------------------------------------------------
# apply_remediation — risk_score flows into DynamoDB item
# ---------------------------------------------------------------------------

class TestApplyRemediationRiskScore:

    def _run_apply(self, risk_score=72):
        import remediation as rem
        mock_table = MagicMock()
        mock_db    = MagicMock()
        mock_db.Table.return_value = mock_table
        orig_sim = rem.SIMULATION_MODE
        rem.SIMULATION_MODE = True
        with patch("boto3.resource", return_value=mock_db), \
             patch("boto3.client", return_value=MagicMock()):
            rem.apply_remediation(
                score_result      = _score_result(-0.10),
                xai_result        = _xai_result(),
                threat_result     = _threat_result(risk_score=risk_score),
                policy_result     = _policy_result(),
                validation_result = _validation_result(),
                raw_event         = _raw_event(),
                event_id          = "test-event-001",
            )
        rem.SIMULATION_MODE = orig_sim
        assert mock_table.put_item.called
        return mock_table.put_item.call_args[1]["Item"]

    def test_risk_score_from_threat_result_stored(self):
        item = self._run_apply(risk_score=88)
        assert item["riskScore"] == 88

    def test_remediation_status_is_simulated(self):
        item = self._run_apply()
        assert item["remediation_status"] == "SIMULATED"

    def test_is_anomaly_true(self):
        item = self._run_apply()
        assert item["isAnomaly"] is True

    def test_threat_category_stored(self):
        item = self._run_apply()
        assert item["threat_category"] == "PRIVILEGE_ESCALATION"

