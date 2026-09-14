"""
Full validation test suite for Phases 0-6.
Tests everything that can be validated WITHOUT AWS credentials.
Run from project root: python -m pytest tests/ -v --tb=short
"""

import sys, json, numpy as np, pandas as pd
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# ============================================================
# SECTION 1: Feature Contract (Phase 0)
# ============================================================
from feature_contract import (
    FEATURE_NAMES, CATEGORICAL_FEATURES,
    KNOWN_EVENT_NAMES, KNOWN_REGIONS, KNOWN_USER_TYPES,
    extract_features, build_dataframe, _extract_hour,
    PRIVILEGE_ESCALATION_EVENTS, DEFENSE_EVASION_EVENTS, RESOURCE_EXFILTRATION_EVENTS,
)

def _eb(event_name, region, user_type, event_time):
    """Helper: build EventBridge-style CloudTrail event."""
    return {"detail": {
        "eventID": "test-id-001",
        "eventName": event_name,
        "eventTime": event_time,
        "eventSource": "iam.amazonaws.com",
        "awsRegion": region,
        "sourceIPAddress": "1.2.3.4",
        "userIdentity": {"type": user_type, "arn": "arn:aws:iam::123456789012:user/alice"},
    }}

class TestFeatureExtraction:
    def test_all_five_features_present(self):
        r = extract_features(_eb("ListBuckets","us-east-1","IAMUser","2020-01-01T10:00:00Z"))
        assert set(r.keys()) == set(FEATURE_NAMES)

    def test_event_name_extracted(self):
        r = extract_features(_eb("CreateAccessKey","us-east-1","IAMUser","2020-01-01T02:00:00Z"))
        assert r["eventName"] == "CreateAccessKey"

    def test_hour_extracted_correctly(self):
        r = extract_features(_eb("DeleteTrail","us-east-1","Root","2020-01-01T03:15:00Z"))
        assert r["hour"] == 3

    def test_hour_minus_one_for_truncated_timestamp(self):
        r = extract_features(_eb("ListBuckets","us-east-1","IAMUser","2017-02"))
        assert r["hour"] == -1

    def test_is_root_one_for_root(self):
        r = extract_features(_eb("DeleteTrail","us-east-1","Root","2020-01-01T04:00:00Z"))
        assert r["isRoot"] == 1
        assert r["userIdentitytype"] == "Root"

    def test_is_root_zero_for_iam_user(self):
        r = extract_features(_eb("ListBuckets","us-east-1","IAMUser","2020-01-01T10:00:00Z"))
        assert r["isRoot"] == 0

    def test_flat_event_no_detail_wrapper(self):
        flat = {"eventName": "GetObject","eventTime": "2020-01-01T14:00:00Z",
                "awsRegion": "us-west-2", "userIdentity": {"type":"AssumedRole","arn":"arn:x"}}
        r = extract_features(flat)
        assert r["eventName"] == "GetObject"
        assert r["hour"] == 14

    def test_missing_fields_do_not_crash(self):
        r = extract_features({})
        assert "eventName" in r
        assert r["isRoot"] == 0


class TestHourExtraction:
    def test_iso8601_full(self):  assert _extract_hour("2020-01-01T03:15:00Z") == 3
    def test_iso8601_midnight(self): assert _extract_hour("2020-01-01T00:00:00Z") == 0
    def test_iso8601_evening(self): assert _extract_hour("2020-01-01T22:59:00Z") == 22
    def test_truncated_returns_minus_one(self): assert _extract_hour("2017-02") == -1
    def test_empty_returns_minus_one(self): assert _extract_hour("") == -1
    def test_none_like_empty(self): assert _extract_hour(None) == -1


class TestVocabularies:
    def test_event_names_are_sorted(self):
        assert KNOWN_EVENT_NAMES == sorted(KNOWN_EVENT_NAMES)
    def test_regions_are_sorted(self):
        assert KNOWN_REGIONS == sorted(KNOWN_REGIONS)
    def test_user_types_are_sorted(self):
        assert KNOWN_USER_TYPES == sorted(KNOWN_USER_TYPES)
    def test_privilege_escalation_events_not_empty(self):
        assert len(PRIVILEGE_ESCALATION_EVENTS) > 0
        assert "CreateAccessKey" in PRIVILEGE_ESCALATION_EVENTS
    def test_defense_evasion_events_not_empty(self):
        assert len(DEFENSE_EVASION_EVENTS) > 0
        assert "DeleteTrail" in DEFENSE_EVASION_EVENTS


# ============================================================
# SECTION 2: Encoder (Phase 0)
# ============================================================
import joblib

ENC_PATH = Path(__file__).parent.parent / "ml" / "encoder.pkl"
MOD_PATH = Path(__file__).parent.parent / "ml" / "model.pkl"

@pytest.fixture(scope="module")
def encoder():
    if not ENC_PATH.exists(): pytest.skip("encoder.pkl missing — run retrain_real.py")
    return joblib.load(ENC_PATH)

@pytest.fixture(scope="module")
def model():
    if not MOD_PATH.exists(): pytest.skip("model.pkl missing — run retrain_real.py")
    return joblib.load(MOD_PATH)

def _encode(enc, event_name, user_type, region):
    df = pd.DataFrame([[event_name, user_type, region]], columns=CATEGORICAL_FEATURES)
    return enc.transform(df)[0]

class TestEncoderDeterminism:
    """THE critical test: proves the cat.codes bug is fixed."""
    def test_same_string_same_code_every_time(self, encoder):
        codes = [_encode(encoder, "ListBuckets", "IAMUser", "us-east-1") for _ in range(10)]
        assert all((c == codes[0]).all() for c in codes), "Non-deterministic encoding detected!"

    def test_unseen_event_name_returns_minus_one(self, encoder):
        code = _encode(encoder, "CompletelyUnknownEvent_XYZ999", "IAMUser", "us-east-1")
        assert code[0] == -1.0

    def test_unseen_region_returns_minus_one(self, encoder):
        code = _encode(encoder, "ListBuckets", "IAMUser", "xy-fake-99")
        assert code[2] == -1.0

    def test_known_event_does_not_return_minus_one(self, encoder):
        code = _encode(encoder, "ListBuckets", "IAMUser", "us-east-1")
        assert code[0] != -1.0

    def test_create_access_key_encodes_consistently(self, encoder):
        c1 = _encode(encoder, "CreateAccessKey", "Root", "us-west-2")
        c2 = _encode(encoder, "CreateAccessKey", "Root", "us-west-2")
        np.testing.assert_array_equal(c1, c2)


# ============================================================
# SECTION 3: Model Inference (Phase 1)
# ============================================================

def _score(enc, mod, event_name, hour, user_type, region, is_root):
    cat = _encode(enc, event_name, user_type, region)
    vec = np.array([[cat[0], float(hour), cat[1], cat[2], float(is_root)]])
    return float(mod.decision_function(vec)[0])

class TestModelInference:
    def test_create_access_key_root_2am_is_anomalous(self, encoder, model):
        s = _score(encoder, model, "CreateAccessKey", 2, "Root", "us-west-2", 1)
        assert s < 0, f"Expected anomalous score, got {s}"

    def test_delete_trail_root_3am_is_anomalous(self, encoder, model):
        s = _score(encoder, model, "DeleteTrail", 3, "Root", "us-east-1", 1)
        assert s < 0, f"Expected anomalous score, got {s}"

    def test_list_buckets_daytime_is_normal(self, encoder, model):
        s = _score(encoder, model, "ListBuckets", 10, "IAMUser", "us-east-1", 0)
        assert s > 0, f"Expected normal score, got {s}"

    def test_describe_instances_daytime_is_near_normal(self, encoder, model):
        # DescribeInstances at 14:00 as AssumedRole scores near-zero (-0.020).
        # The model sees it as borderline; it is NOT flagged by the pipeline
        # because ANOMALY_SCORE_THRESHOLD is -0.02 and the pipeline uses strict <.
        # This test validates that the score is above -0.10 (not deeply anomalous).
        s = _score(encoder, model, "DescribeInstances", 14, "AssumedRole", "us-east-1", 0)
        assert s > -0.10, f"DescribeInstances should not be deeply anomalous, got {s}"

    def test_anomaly_score_is_float(self, encoder, model):
        s = _score(encoder, model, "ListBuckets", 10, "IAMUser", "us-east-1", 0)
        assert isinstance(s, float)

    def test_unseen_event_does_not_crash(self, encoder, model):
        s = _score(encoder, model, "UnknownEventXYZ999", 14, "IAMUser", "us-east-1", 0)
        assert isinstance(s, float)


# ============================================================
# SECTION 4: SHAP XAI (Phase 2)
# ============================================================

class TestSHAPExplainer:
    def _run_explain(self, model, event_name, hour, user_type, region, is_root):
        import joblib
        enc = joblib.load(ENC_PATH)
        from xai_explainer import explain
        cat = _encode(enc, event_name, user_type, region)
        vec = np.array([[cat[0], float(hour), cat[1], cat[2], float(is_root)]])
        return explain(model, vec, FEATURE_NAMES)

    def test_shap_returns_all_features(self, model):
        r = self._run_explain(model, "CreateAccessKey", 2, "Root", "us-east-1", 1)
        assert set(r["shap_values"].keys()) == set(FEATURE_NAMES)

    def test_shap_top_feature_is_string(self, model):
        r = self._run_explain(model, "DeleteTrail", 3, "Root", "us-east-1", 1)
        assert isinstance(r["top_feature"], str)
        assert r["top_feature"] in FEATURE_NAMES

    def test_shap_top_shap_value_is_negative_for_anomaly(self, model):
        """Key polarity test: anomalous feature must have negative SHAP."""
        r = self._run_explain(model, "CreateAccessKey", 2, "Root", "us-east-1", 1)
        assert r["top_shap_value"] < 0, \
            f"Top SHAP value should be negative for anomalous event, got {r['top_shap_value']}"

    def test_attribution_confidence_between_0_and_1(self, model):
        r = self._run_explain(model, "DeleteTrail", 3, "Root", "us-east-1", 1)
        assert 0 <= r["attribution_confidence"] <= 1

    def test_anomalous_features_list_all_negative(self, model):
        r = self._run_explain(model, "CreateAccessKey", 2, "Root", "us-east-1", 1)
        for f in r["anomalous_features"]:
            assert f["shap_value"] < 0, f"Non-negative SHAP in anomalous_features: {f}"


# ============================================================
# SECTION 5: Threat Classifier (Phase 3)
# ============================================================
from threat_classifier import classify_threat

def _fake_xai(top_feature, top_shap=-0.4, confidence=0.65):
    """Build a minimal xai_result for testing threat_classifier."""
    return {
        "top_feature": top_feature,
        "top_shap_value": top_shap,
        "attribution_confidence": confidence,
        "is_uncertain": confidence < 0.30,
        "anomalous_features": [{"feature": top_feature, "shap_value": top_shap}],
    }

class TestThreatClassifier:
    def test_privilege_escalation_detected(self):
        xai = _fake_xai("eventName")
        feats = {"eventName": "CreateAccessKey", "userIdentitytype": "IAMUser",
                 "awsRegion": "us-east-1", "hour": 10, "isRoot": 0}
        r = classify_threat(xai, feats)
        assert r["threat_category"] == "PRIVILEGE_ESCALATION"

    def test_defense_evasion_detected(self):
        xai = _fake_xai("eventName")
        feats = {"eventName": "DeleteTrail", "userIdentitytype": "IAMUser",
                 "awsRegion": "us-east-1", "hour": 10, "isRoot": 0}
        r = classify_threat(xai, feats)
        assert r["threat_category"] == "DEFENSE_EVASION"

    def test_geographic_anomaly_detected(self):
        xai = _fake_xai("awsRegion")
        feats = {"eventName": "ListBuckets", "userIdentitytype": "IAMUser",
                 "awsRegion": "ap-southeast-2", "hour": 14, "isRoot": 0}
        r = classify_threat(xai, feats)
        assert r["threat_category"] == "GEOGRAPHIC_ANOMALY"

    def test_temporal_anomaly_detected_at_3am(self):
        xai = _fake_xai("hour")
        feats = {"eventName": "GetObject", "userIdentitytype": "IAMUser",
                 "awsRegion": "us-east-1", "hour": 3, "isRoot": 0}
        r = classify_threat(xai, feats)
        assert r["threat_category"] == "TEMPORAL_ANOMALY"

    def test_credential_anomaly_for_root(self):
        xai = _fake_xai("userIdentitytype")
        feats = {"eventName": "GetObject", "userIdentitytype": "Root",
                 "awsRegion": "us-east-1", "hour": 10, "isRoot": 1}
        r = classify_threat(xai, feats)
        assert r["threat_category"] == "CREDENTIAL_ANOMALY"
        assert r["enforcement_eligible"] == False  # root cannot have inline policies

    def test_uncertain_when_low_confidence(self):
        xai = _fake_xai("hour", confidence=0.15)
        feats = {"eventName": "ListBuckets", "userIdentitytype": "IAMUser",
                 "awsRegion": "us-east-1", "hour": 3, "isRoot": 0}
        r = classify_threat(xai, feats)
        assert r["threat_category"] == "UNCERTAIN"
        assert r["enforcement_eligible"] == False

    def test_all_results_have_mitre_field(self):
        for event, feat in [("CreateAccessKey","eventName"),("DeleteTrail","eventName"),
                             ("ListBuckets","awsRegion"),("GetObject","hour")]:
            xai = _fake_xai(feat)
            feats = {"eventName": event, "userIdentitytype": "IAMUser",
                     "awsRegion": "us-east-1", "hour": 3, "isRoot": 0}
            r = classify_threat(xai, feats)
            assert "mitre_technique" in r
            assert "severity" in r


# ============================================================
# SECTION 6: IAM Policy Generator (Phase 4)
# ============================================================
from iam_generator import generate_policy

def _threat(category, enforce=True):
    return {"threat_category": category, "enforcement_eligible": enforce,
            "severity": "Critical", "label": category}

def _raw_event(user_type="IAMUser", arn="arn:aws:iam::123456789012:user/alice"):
    return {"detail": {"eventTime": "2020-01-01T03:00:00Z", "eventSource": "iam.amazonaws.com",
                       "userIdentity": {"type": user_type, "arn": arn}}}

def _feats(region="us-east-1", hour=3, user_type="IAMUser"):
    return {"awsRegion": region, "hour": hour, "userIdentitytype": user_type,
            "eventName": "CreateAccessKey", "isRoot": 0}

class TestIAMGenerator:
    def test_policy_json_is_valid_json(self):
        r = generate_policy(_threat("PRIVILEGE_ESCALATION"), _feats(), _raw_event(), "abc12345")
        parsed = json.loads(r["policy_json"])
        assert "Version" in parsed
        assert "Statement" in parsed
        assert parsed["Version"] == "2012-10-17"

    def test_policy_is_deny(self):
        r = generate_policy(_threat("PRIVILEGE_ESCALATION"), _feats(), _raw_event(), "abc12345")
        stmt = json.loads(r["policy_json"])["Statement"][0]
        assert stmt["Effect"] == "Deny"

    def test_policy_name_contains_event_id_prefix(self):
        r = generate_policy(_threat("GEOGRAPHIC_ANOMALY"), _feats(), _raw_event(), "abcdef99-test")
        assert r["policy_name"] == "CloudGuard-abcdef99"

    def test_root_principal_not_enforcement_eligible(self):
        r = generate_policy(
            _threat("CREDENTIAL_ANOMALY"),
            _feats(user_type="Root"),
            _raw_event(user_type="Root", arn="arn:aws:iam::123456789012:root"),
            "abc12345"
        )
        assert r["enforcement_eligible"] == False
        assert r["skip_reason"] is not None

    def test_missing_arn_not_enforcement_eligible(self):
        raw = {"detail": {"userIdentity": {"type": "IAMUser", "arn": ""}}}
        r = generate_policy(_threat("PRIVILEGE_ESCALATION"), _feats(), raw, "abc12345")
        assert r["enforcement_eligible"] == False

    def test_all_six_categories_produce_valid_json(self):
        cats = ["PRIVILEGE_ESCALATION","DEFENSE_EVASION","GEOGRAPHIC_ANOMALY",
                "TEMPORAL_ANOMALY","RESOURCE_EXFILTRATION","CREDENTIAL_ANOMALY"]
        for cat in cats:
            r = generate_policy(_threat(cat), _feats(), _raw_event(), "test1234")
            parsed = json.loads(r["policy_json"])
            assert parsed["Version"] == "2012-10-17", f"Bad policy for {cat}"

    def test_geographic_anomaly_policy_has_region_condition(self):
        r = generate_policy(_threat("GEOGRAPHIC_ANOMALY"), _feats(region="ap-southeast-2"),
                            _raw_event(), "abc12345")
        stmt = json.loads(r["policy_json"])["Statement"][0]
        assert "Condition" in stmt
        cond = stmt["Condition"]
        # Should contain StringEquals on region
        assert "StringEquals" in cond

    def test_privilege_escalation_denies_iam_actions(self):
        r = generate_policy(_threat("PRIVILEGE_ESCALATION"), _feats(), _raw_event(), "abc12345")
        stmt = json.loads(r["policy_json"])["Statement"][0]
        actions = stmt["Action"]
        assert any("iam:" in a for a in actions)


# ============================================================
# SECTION 7: Policy Validator (Phase 5) — LOCAL only
# Validates JSON parsing and error handling WITHOUT AWS creds
# ============================================================
from policy_validator import validate_policy
import unittest.mock as mock

class TestPolicyValidatorLocal:
    def test_malformed_json_returns_error_status(self):
        r = validate_policy("THIS IS NOT JSON", "IDENTITY_POLICY")
        assert r["proceed"] == False
        assert r["validation_status"] == "ERROR"
        assert "Malformed" in r["blocking_reason"]

    def test_malformed_json_does_not_crash(self):
        r = validate_policy("{unclosed", "IDENTITY_POLICY")
        assert isinstance(r, dict)
        assert "proceed" in r

    def test_api_error_is_caught_gracefully(self):
        """Simulate boto3 ClientError without real AWS credentials."""
        from botocore.exceptions import ClientError
        error_response = {"Error": {"Code": "AccessDeniedException", "Message": "No access"}}
        with mock.patch("policy_validator.boto3") as mock_boto:
            mock_client = mock.MagicMock()
            mock_boto.client.return_value = mock_client
            mock_client.validate_policy.side_effect = ClientError(error_response, "validate_policy")
            r = validate_policy('{"Version":"2012-10-17","Statement":[]}', "IDENTITY_POLICY")
        assert r["proceed"] == False
        assert r["validation_status"] == "ERROR"

    def test_clean_policy_proceeds(self):
        """Simulate a clean (no findings) Access Analyzer response."""
        with mock.patch("policy_validator.boto3") as mock_boto:
            mock_client = mock.MagicMock()
            mock_boto.client.return_value = mock_client
            mock_client.validate_policy.return_value = {"findings": []}
            policy = json.dumps({"Version":"2012-10-17",
                "Statement":[{"Effect":"Deny","Action":["iam:CreateAccessKey"],"Resource":"*"}]})
            r = validate_policy(policy, "IDENTITY_POLICY")
        assert r["proceed"] == True
        assert r["validation_status"] in ["CLEAN", "SUGGESTION_ONLY"]

    def test_error_finding_blocks_policy(self):
        with mock.patch("policy_validator.boto3") as mock_boto:
            mock_client = mock.MagicMock()
            mock_boto.client.return_value = mock_client
            mock_client.validate_policy.return_value = {
                "findings": [{"findingType": "ERROR", "issueCode": "INVALID_ACTION",
                               "learnMoreLink": "https://example.com", "findingDetails": "bad"}]
            }
            r = validate_policy('{"Version":"2012-10-17","Statement":[]}', "IDENTITY_POLICY")
        assert r["proceed"] == False
        assert r["validation_status"] == "BLOCKED"

    def test_security_warning_blocks_policy(self):
        with mock.patch("policy_validator.boto3") as mock_boto:
            mock_client = mock.MagicMock()
            mock_boto.client.return_value = mock_client
            mock_client.validate_policy.return_value = {
                "findings": [{"findingType": "SECURITY_WARNING", "issueCode": "PASS_ROLE_STAR",
                               "learnMoreLink": "https://example.com", "findingDetails": "risky"}]
            }
            r = validate_policy('{"Version":"2012-10-17","Statement":[]}', "IDENTITY_POLICY")
        assert r["proceed"] == False
        assert r["validation_status"] == "BLOCKED"

    def test_warning_finding_allows_but_requires_approval(self):
        with mock.patch("policy_validator.boto3") as mock_boto:
            mock_client = mock.MagicMock()
            mock_boto.client.return_value = mock_client
            mock_client.validate_policy.return_value = {
                "findings": [{"findingType": "WARNING", "issueCode": "SOME_WARNING",
                               "learnMoreLink": "https://example.com", "findingDetails": "minor"}]
            }
            r = validate_policy('{"Version":"2012-10-17","Statement":[]}', "IDENTITY_POLICY")
        assert r["proceed"] == True
        assert r["requires_approval"] == True
        assert r["validation_status"] == "WARNING_PRESENT"

    def test_suggestion_finding_allows_no_approval_needed(self):
        with mock.patch("policy_validator.boto3") as mock_boto:
            mock_client = mock.MagicMock()
            mock_boto.client.return_value = mock_client
            mock_client.validate_policy.return_value = {
                "findings": [{"findingType": "SUGGESTION", "issueCode": "SUGGEST_X",
                               "learnMoreLink": "https://example.com", "findingDetails": "tip"}]
            }
            r = validate_policy('{"Version":"2012-10-17","Statement":[]}', "IDENTITY_POLICY")
        assert r["proceed"] == True
        assert r["requires_approval"] == False


# ============================================================
# SECTION 8: Remediation Safety Gate (Phase 6)
# ============================================================
from remediation import _determine_status
from threat_classifier import compute_risk_score, compute_risk_score_normal

class TestRemediationSafety:
    def test_simulation_mode_returns_simulated(self, monkeypatch):
        monkeypatch.setattr("remediation.SIMULATION_MODE", True)
        status = _determine_status(
            {"enforcement_eligible": True},
            {"proceed": True, "requires_approval": False}
        )
        assert status == "SIMULATED"

    def test_blocked_validation_returns_blocked(self, monkeypatch):
        monkeypatch.setattr("remediation.SIMULATION_MODE", False)
        status = _determine_status(
            {"enforcement_eligible": True},
            {"proceed": False, "requires_approval": False}
        )
        assert status == "BLOCKED"

    def test_requires_approval_returns_pending(self, monkeypatch):
        monkeypatch.setattr("remediation.SIMULATION_MODE", False)
        status = _determine_status(
            {"enforcement_eligible": True},
            {"proceed": True, "requires_approval": True}
        )
        assert status == "PENDING_APPROVAL"

    def test_not_enforcement_eligible_returns_simulated(self, monkeypatch):
        monkeypatch.setattr("remediation.SIMULATION_MODE", False)
        status = _determine_status(
            {"enforcement_eligible": False},
            {"proceed": True, "requires_approval": False}
        )
        assert status == "SIMULATED"

    def test_risk_score_highly_anomalous(self):
        # Use the canonical risk score function (severity=Critical, high confidence)
        score = compute_risk_score(-0.10, "Critical", 0.8)
        assert score > 50, f"Critical event with score -0.10 should map to >50, got {score}"

    def test_risk_score_normal_event(self):
        score = compute_risk_score_normal(0.15)
        assert score == 0, f"Normal score +0.15 should map to 0, got {score}"

    def test_risk_score_clamped_0_to_100(self):
        assert 0 <= compute_risk_score(-0.5, "Critical", 1.0) <= 100
        assert 0 <= compute_risk_score(0.5, "Low", 0.0) <= 100


# ============================================================
# SECTION 9: End-to-end pipeline (no AWS) (Phase 0-6)
# ============================================================

class TestEndToEndLocal:
    """Run the full pipeline with mocked DynamoDB and SNS."""

    def test_full_pipeline_anomalous_event(self, encoder, model, monkeypatch):
        import remediation as rem
        import lambda_function as lf

        # Patch DynamoDB and SNS so no AWS calls are made
        monkeypatch.setattr("remediation.SIMULATION_MODE", True)
        mock_table = mock.MagicMock()
        monkeypatch.setattr("remediation._get_table", lambda: mock_table)
        monkeypatch.setattr("remediation.SNS_TOPIC_ARN", "")

        # Mock Access Analyzer
        with mock.patch("policy_validator.boto3") as mock_boto:
            mock_client = mock.MagicMock()
            mock_boto.client.return_value = mock_client
            mock_client.validate_policy.return_value = {"findings": []}

            event = _eb("CreateAccessKey", "us-west-2", "Root", "2020-01-01T02:00:00Z")
            result = lf.handler(event, None)

        assert result["statusCode"] == 200
        body = result["body"]
        assert body["is_anomaly"] == True
        assert body["pipeline"] == "full"
        assert "threat_category" in body
        assert "validation_status" in body
        assert body["remediation_status"] == "SIMULATED"
        # risk_score must be present and in valid range (Phase 1)
        assert "risk_score" in body, "risk_score must be in pipeline return dict"
        assert 0 <= body["risk_score"] <= 100
        # Verify DynamoDB put_item was called
        assert mock_table.put_item.called

    def test_full_pipeline_normal_event(self, encoder, model, monkeypatch):
        import remediation as rem
        import lambda_function as lf

        monkeypatch.setattr("remediation.SIMULATION_MODE", True)
        mock_table = mock.MagicMock()
        monkeypatch.setattr("remediation._get_table", lambda: mock_table)

        event = _eb("ListBuckets", "us-east-1", "IAMUser", "2020-01-01T10:00:00Z")
        result = lf.handler(event, None)

        assert result["statusCode"] == 200
        body = result["body"]
        assert body["is_anomaly"] == False
        assert body["pipeline"] == "normal-exit"
