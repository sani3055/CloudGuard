"""
test_feature_contract.py
========================
Phase 0 + Phase 1 unit tests.

Run from project root:
  python -m pytest tests/ -v

These tests do NOT require AWS credentials.
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

# Make ml/ and backend/ importable
sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from feature_contract import (
    FEATURE_NAMES,
    CATEGORICAL_FEATURES,
    KNOWN_EVENT_NAMES,
    KNOWN_REGIONS,
    KNOWN_USER_TYPES,
    extract_features,
    build_dataframe,
    _extract_hour,
)


# ---------------------------------------------------------------------------
# extract_features
# ---------------------------------------------------------------------------

class TestExtractFeatures:

    def _make_eventbridge(self, event_name, region, user_type, event_time, is_root=False):
        return {
            "detail": {
                "eventID": "abc-123",
                "eventName": event_name,
                "eventTime": event_time,
                "eventSource": "iam.amazonaws.com",
                "awsRegion": region,
                "sourceIPAddress": "1.2.3.4",
                "userIdentity": {
                    "type": user_type,
                    "arn": f"arn:aws:iam::123456789012:user/testuser",
                },
            }
        }

    def test_extracts_event_name(self):
        event = self._make_eventbridge("CreateAccessKey", "us-east-1", "IAMUser", "2017-02-01T03:00:00Z")
        result = extract_features(event)
        assert result["eventName"] == "CreateAccessKey"

    def test_extracts_region(self):
        event = self._make_eventbridge("ListBuckets", "ap-southeast-2", "IAMUser", "2017-02-01T14:00:00Z")
        result = extract_features(event)
        assert result["awsRegion"] == "ap-southeast-2"

    def test_extracts_hour_from_full_timestamp(self):
        event = self._make_eventbridge("ListBuckets", "us-east-1", "IAMUser", "2017-02-01T03:15:00Z")
        result = extract_features(event)
        assert result["hour"] == 3

    def test_hour_fallback_for_truncated_timestamp(self):
        # Real dataset has truncated timestamps like "2017-02"
        event = self._make_eventbridge("ListBuckets", "us-east-1", "IAMUser", "2017-02")
        result = extract_features(event)
        assert result["hour"] == -1  # unknown hour

    def test_is_root_derived_correctly(self):
        event = self._make_eventbridge("DeleteTrail", "us-east-1", "Root", "2017-02-01T04:00:00Z")
        result = extract_features(event)
        assert result["isRoot"] == 1
        assert result["userIdentitytype"] == "Root"

    def test_is_root_false_for_iam_user(self):
        event = self._make_eventbridge("ListBuckets", "us-east-1", "IAMUser", "2017-02-01T10:00:00Z")
        result = extract_features(event)
        assert result["isRoot"] == 0

    def test_flat_event_without_detail_wrapper(self):
        flat_event = {
            "eventName": "GetObject",
            "eventTime": "2017-02-01T12:00:00Z",
            "awsRegion": "us-west-2",
            "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:iam::123:role/r"},
            "sourceIPAddress": "5.5.5.5",
        }
        result = extract_features(flat_event)
        assert result["eventName"] == "GetObject"
        assert result["awsRegion"] == "us-west-2"
        assert result["hour"] == 12

    def test_all_feature_names_present_in_output(self):
        event = self._make_eventbridge("ListBuckets", "us-east-1", "IAMUser", "2017-02-01T10:00:00Z")
        result = extract_features(event)
        for name in FEATURE_NAMES:
            assert name in result, f"Missing feature: {name}"


# ---------------------------------------------------------------------------
# Encoding round-trip
# ---------------------------------------------------------------------------

class TestEncodingRoundTrip:

    def setup_method(self):
        import joblib
        encoder_path = Path(__file__).parent.parent / "ml" / "encoder.pkl"
        if not encoder_path.exists():
            pytest.skip("encoder.pkl not found — run ml/retrain_real.py first")
        self.encoder = joblib.load(encoder_path)

    def test_known_event_encodes_consistently(self):
        df1 = pd.DataFrame([["ListBuckets", "IAMUser", "us-east-1"]], columns=CATEGORICAL_FEATURES)
        df2 = pd.DataFrame([["ListBuckets", "IAMUser", "us-east-1"]], columns=CATEGORICAL_FEATURES)
        enc1 = self.encoder.transform(df1)
        enc2 = self.encoder.transform(df2)
        np.testing.assert_array_equal(enc1, enc2)

    def test_same_string_produces_same_code_every_call(self):
        """Core test: reproduces the cat.codes bug. This must NEVER vary."""
        results = []
        for _ in range(5):
            df = pd.DataFrame([["CreateAccessKey", "Root", "us-west-2"]], columns=CATEGORICAL_FEATURES)
            enc = self.encoder.transform(df)
            results.append(enc[0].tolist())
        assert all(r == results[0] for r in results)

    def test_unseen_event_name_returns_minus_one_not_crash(self):
        df = pd.DataFrame([["ThisEventDoesNotExist_XYZ999", "IAMUser", "us-east-1"]], columns=CATEGORICAL_FEATURES)
        enc = self.encoder.transform(df)
        assert enc[0, 0] == -1, "Unseen eventName must encode to unknown_value=-1"

    def test_unseen_region_returns_minus_one(self):
        df = pd.DataFrame([["ListBuckets", "IAMUser", "me-south-99"]], columns=CATEGORICAL_FEATURES)
        enc = self.encoder.transform(df)
        assert enc[0, 2] == -1


# ---------------------------------------------------------------------------
# Model predictions on known events
# ---------------------------------------------------------------------------

class TestModelPredictions:

    def setup_method(self):
        import joblib
        ml_dir = Path(__file__).parent.parent / "ml"
        encoder_path = ml_dir / "encoder.pkl"
        model_path   = ml_dir / "model.pkl"
        if not encoder_path.exists() or not model_path.exists():
            pytest.skip("encoder.pkl or model.pkl not found — run retrain_real.py first")
        self.encoder = joblib.load(encoder_path)
        self.model   = joblib.load(model_path)

    def _score(self, event_name, hour, user_type, region, is_root):
        df  = pd.DataFrame([[event_name, user_type, region]], columns=CATEGORICAL_FEATURES)
        enc = self.encoder.transform(df)
        vec = np.array([[enc[0,0], hour, enc[0,1], enc[0,2], float(is_root)]])
        return float(self.model.decision_function(vec)[0])

    def test_create_access_key_is_anomalous(self):
        score = self._score("CreateAccessKey", 2, "Root", "us-west-2", 1)
        assert score < 0, f"CreateAccessKey by Root at 2am should be anomalous, got score={score}"

    def test_list_buckets_is_normal(self):
        score = self._score("ListBuckets", 10, "IAMUser", "us-east-1", 0)
        assert score > 0, f"ListBuckets at 10am by IAMUser should be normal, got score={score}"

    def test_delete_trail_is_anomalous(self):
        score = self._score("DeleteTrail", 3, "Root", "us-east-1", 1)
        assert score < 0, f"DeleteTrail by Root at 3am should be anomalous, got score={score}"
