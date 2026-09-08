"""
retrain_real.py
===============
Retrains the CloudGuard Isolation Forest on the real CloudTrail dataset
(dec12_18features.csv, 1.93M rows) using the deterministic OrdinalEncoder
defined in feature_contract.py.

Outputs:
  ml/encoder.pkl  â€” fitted OrdinalEncoder (MUST be committed and used at inference)
  ml/model.pkl    â€” fitted IsolationForest

Run from the ml/ directory:
  python retrain_real.py

Do NOT run train.py after this â€” it uses the old fabricated dataset.
"""

import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OrdinalEncoder

# ---------------------------------------------------------------------------
# Imports from feature_contract (same directory)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))
from feature_contract import (
    FEATURE_NAMES,
    CATEGORICAL_FEATURES,
    KNOWN_EVENT_NAMES,
    KNOWN_REGIONS,
    KNOWN_USER_TYPES,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DATA_PATH      = Path(__file__).parent.parent / "data" / "dec12_18features.csv"
ENCODER_PATH   = Path(__file__).parent / "encoder.pkl"
MODEL_PATH     = Path(__file__).parent / "model.pkl"

# Isolation Forest hyperparameters
N_ESTIMATORS   = 100
CONTAMINATION  = 0.05   # ~5% of real CloudTrail events expected to be anomalous
MAX_FEATURES   = 1.0
RANDOM_STATE   = 42
CHUNK_SIZE     = 100_000  # rows per chunk for memory-efficient loading

# Column name mapping: real CSV  â†’  feature_contract names
COLUMN_MAP = {
    "eventName":         "eventName",
    "awsRegion":         "awsRegion",
    "userIdentitytype":  "userIdentitytype",
    "eventTime":         "_eventTime",   # extracted to hour below
}

# ---------------------------------------------------------------------------
# Step 1: Build and fit the OrdinalEncoder with known categories
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 1: Fitting OrdinalEncoder on known category vocabularies")
print("=" * 60)

# Categories list must match the order of CATEGORICAL_FEATURES
# ["eventName", "userIdentitytype", "awsRegion"]
categories = [
    KNOWN_EVENT_NAMES,    # eventName
    KNOWN_USER_TYPES,     # userIdentitytype
    KNOWN_REGIONS,        # awsRegion
]

encoder = OrdinalEncoder(
    categories=categories,
    handle_unknown="use_encoded_value",
    unknown_value=-1,   # unseen values at inference time â†’ -1
    dtype=np.float64,
)

# Fit on a dummy frame that contains all known categories to initialise
dummy = pd.DataFrame({
    "eventName":        KNOWN_EVENT_NAMES[:1],
    "userIdentitytype": KNOWN_USER_TYPES[:1],
    "awsRegion":        KNOWN_REGIONS[:1],
})
encoder.fit(dummy)
print(f"  eventName  categories : {len(encoder.categories_[0])}")
print(f"  userType   categories : {len(encoder.categories_[1])}")
print(f"  awsRegion  categories : {len(encoder.categories_[2])}")

joblib.dump(encoder, ENCODER_PATH)
print(f"  Saved â†’ {ENCODER_PATH}\n")

# ---------------------------------------------------------------------------
# Step 2: Load real data in chunks, extract & encode features
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 2: Loading and encoding real CloudTrail data")
print("=" * 60)

usecols = ["eventName", "awsRegion", "userIdentitytype", "eventTime"]
encoded_chunks = []
total_rows     = 0
t0             = time.time()

for i, chunk in enumerate(pd.read_csv(DATA_PATH, usecols=usecols, chunksize=CHUNK_SIZE)):
    # --- Derive hour from eventTime ---
    # Real format examples: "2017-02", "2017-02-01T12:34:56Z"
    # Many rows in this dataset have truncated timestamps â†’ hour = -1 (unknown)
    def _parse_hour(ts_str: str) -> int:
        import re
        m = re.search(r"T(\d{2}):", str(ts_str))
        return int(m.group(1)) if m else -1

    chunk["hour"] = chunk["eventTime"].apply(_parse_hour)

    # --- isRoot (derived) ---
    chunk["isRoot"] = (chunk["userIdentitytype"] == "Root").astype(int)

    # --- Encode categorical columns ---
    chunk[CATEGORICAL_FEATURES] = encoder.transform(chunk[CATEGORICAL_FEATURES])

    # --- Select only model features in canonical order ---
    X_chunk = chunk[FEATURE_NAMES].values
    encoded_chunks.append(X_chunk)

    total_rows += len(chunk)
    elapsed = time.time() - t0
    print(f"  Chunk {i+1:4d} | rows so far: {total_rows:>10,} | {elapsed:.1f}s")

X = np.vstack(encoded_chunks)
print(f"\n  Total rows encoded: {X.shape[0]:,}")
print(f"  Feature matrix shape: {X.shape}")
print(f"  Memory: {X.nbytes / 1e6:.1f} MB\n")

# ---------------------------------------------------------------------------
# Step 3: Fit Isolation Forest
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 3: Training Isolation Forest")
print("=" * 60)
print(f"  n_estimators : {N_ESTIMATORS}")
print(f"  contamination: {CONTAMINATION}")
print(f"  random_state : {RANDOM_STATE}")

t1 = time.time()
model = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    max_features=MAX_FEATURES,
    random_state=RANDOM_STATE,
    n_jobs=-1,
)
model.fit(X)
elapsed = time.time() - t1
print(f"  Training complete in {elapsed:.1f}s")

# Quick sanity check
preds  = model.predict(X[:1000])
scores = model.decision_function(X[:1000])
n_anomalies = (preds == -1).sum()
print(f"\n  Sanity check (first 1000 rows):")
print(f"    Anomalies detected : {n_anomalies} ({n_anomalies/10:.1f}%)")
print(f"    Score range        : [{scores.min():.4f}, {scores.max():.4f}]")

joblib.dump(model, MODEL_PATH)
print(f"\n  Saved â†’ {MODEL_PATH}\n")

# ---------------------------------------------------------------------------
# Step 4: Verify encoder + model round-trip
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 4: Round-trip verification")
print("=" * 60)

enc_loaded   = joblib.load(ENCODER_PATH)
model_loaded = joblib.load(MODEL_PATH)

test_cases = [
    # (eventName,          hour, userType,      region,       expected_note)
    ("ListBuckets",         10,  "IAMUser",    "us-east-1",  "normal activity"),
    ("DeleteTrail",          3,  "Root",       "us-east-1",  "high-risk: defense evasion"),
    ("CreateAccessKey",      2,  "Root",       "us-west-2",  "high-risk: priv escalation"),
    ("UnknownEventXYZ",     14,  "Unknown",    "us-east-1",  "unseen event name â†’ -1"),
]

for event_name, hour, user_type, region, note in test_cases:
    cat_df  = pd.DataFrame([[event_name, user_type, region]],
                            columns=CATEGORICAL_FEATURES)
    cat_enc = enc_loaded.transform(cat_df)
    is_root = 1 if user_type == "Root" else 0
    row     = np.array([[cat_enc[0, 0], hour, cat_enc[0, 1], cat_enc[0, 2], is_root]])
    pred    = model_loaded.predict(row)[0]
    score   = model_loaded.decision_function(row)[0]
    label   = "ANOMALY" if pred == -1 else "normal"
    print(f"  [{label:7s}] score={score:+.4f}  {event_name!r}  ({note})")

print("\nPhase 0 complete. encoder.pkl and model.pkl are ready.\n")
