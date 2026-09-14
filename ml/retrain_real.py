"""
retrain_real.py
===============
Retrains the CloudGuard Isolation Forest on the real CloudTrail dataset
(dec12_18features.csv, 1.93M rows) using the deterministic OrdinalEncoder
defined in feature_contract.py.

Outputs:
  ml/encoder.pkl       — fitted OrdinalEncoder (MUST be committed and used at inference)
  ml/model.pkl         — fitted IsolationForest (trained on 80% of data)
  ml/eval_report.json  — evaluation report (test set + labeled scenario metrics)

Run from the ml/ directory:
  python retrain_real.py

Do NOT run train.py after this — it uses the old fabricated dataset.

Evaluation design:
  - 80/20 train-test split on real data (reproducible via RANDOM_STATE)
  - IsolationForest fitted on 80% train set only
  - Test set (20%) used for anomaly rate, score distribution, risk distribution,
    and inference throughput — NOT for P/R/F1
  - P/R/F1 computed on a hand-crafted labeled scenario set (~30 events).
    Each scenario has a human-assigned ground truth label (1=anomalous, 0=normal).
    This is the only honest P/R/F1 for an unsupervised model: we provide
    true external labels for a controlled probe set, then check whether the
    model agrees. We do NOT use contamination-derived labels as ground truth.
"""

import json as _json
import os as _os
import re as _re
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import OrdinalEncoder

# ---------------------------------------------------------------------------
# Imports from feature_contract (same directory)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))
from feature_contract import (
    CATEGORICAL_FEATURES,
    DEFENSE_EVASION_EVENTS,
    FEATURE_NAMES,
    KNOWN_EVENT_NAMES,
    KNOWN_REGIONS,
    KNOWN_USER_TYPES,
    PRIVILEGE_ESCALATION_EVENTS,
    RESOURCE_EXFILTRATION_EVENTS,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DATA_PATH        = Path(__file__).parent.parent / "data" / "dec12_18features.csv"
ENCODER_PATH     = Path(__file__).parent / "encoder.pkl"
MODEL_PATH       = Path(__file__).parent / "model.pkl"
EVAL_REPORT_PATH = Path(__file__).parent / "eval_report.json"

# Isolation Forest hyperparameters
N_ESTIMATORS   = 100
CONTAMINATION  = 0.05   # ~5% expected anomaly rate from domain knowledge
MAX_FEATURES   = 1.0
RANDOM_STATE   = 42
CHUNK_SIZE     = 100_000       # rows per chunk for memory-efficient loading
TRAIN_FRACTION = 0.80          # 80/20 train-test split

# Runtime anomaly threshold (matches Lambda default)
ANOMALY_THRESHOLD: float = float(
    _os.environ.get("ANOMALY_SCORE_THRESHOLD", "-0.02")
)


# ---------------------------------------------------------------------------
# Step 1: Build and fit the OrdinalEncoder with known category vocabularies
# ---------------------------------------------------------------------------
# IMPORTANT: The encoder is fitted on the KNOWN_* vocabularies from
# feature_contract.py — NOT on the training data. This is intentional:
# the vocabulary is exhaustive (sourced from the full 1.93M dataset corpus
# during feature_contract authoring) and ensures unknown values at inference
# time are handled deterministically via unknown_value=-1.
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 1: Fitting OrdinalEncoder on known category vocabularies")
print("=" * 60)

categories = [
    KNOWN_EVENT_NAMES,    # eventName
    KNOWN_USER_TYPES,     # userIdentitytype
    KNOWN_REGIONS,        # awsRegion
]

encoder = OrdinalEncoder(
    categories=categories,
    handle_unknown="use_encoded_value",
    unknown_value=-1,       # unseen values at inference → -1
    dtype=np.float64,
)

# Fit on a single-row dummy frame to initialise internal state
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
print(f"  Saved -> {ENCODER_PATH}\n")


# ---------------------------------------------------------------------------
# Step 2: Load real data in chunks, extract & encode features
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 2: Loading and encoding real CloudTrail data (full corpus)")
print("=" * 60)


def _parse_hour(ts_str: str) -> int:
    """Extract UTC hour from eventTime; return -1 if unparseable."""
    for pat in [r"T(\d{2}):", r" (\d{2}):\d{2}:\d{2}"]:
        m = _re.search(pat, str(ts_str))
        if m:
            return int(m.group(1))
    return -1


usecols = ["eventName", "awsRegion", "userIdentitytype", "eventTime"]
encoded_chunks: list = []
total_rows = 0
t0 = time.time()

for i, chunk in enumerate(pd.read_csv(DATA_PATH, usecols=usecols, chunksize=CHUNK_SIZE)):
    chunk["hour"]   = chunk["eventTime"].apply(_parse_hour)
    chunk["isRoot"] = (chunk["userIdentitytype"] == "Root").astype(int)
    chunk[CATEGORICAL_FEATURES] = encoder.transform(chunk[CATEGORICAL_FEATURES])
    encoded_chunks.append(chunk[FEATURE_NAMES].values)
    total_rows += len(chunk)
    print(f"  Chunk {i+1:4d} | rows so far: {total_rows:>10,} | {time.time()-t0:.1f}s")

X = np.vstack(encoded_chunks)
print(f"\n  Total rows encoded : {X.shape[0]:,}")
print(f"  Feature matrix     : {X.shape}  ({X.nbytes / 1e6:.1f} MB)\n")


# ---------------------------------------------------------------------------
# Step 3: 80/20 train-test split
# ---------------------------------------------------------------------------
# WHY split BEFORE fitting?
#   Isolation Forest scores are calibrated relative to the distribution it
#   saw during training. Evaluating on the same rows it trained on would
#   give artificially low (more normal) anomaly scores for every point since
#   the trees were built around those points. The 20% held-out test set
#   gives a genuine out-of-sample view of score distribution and anomaly rate.
#
# WHY NOT use the test set for P/R/F1?
#   The test set has no external ground-truth labels — these are unlabelled
#   production CloudTrail records. Using the model's own threshold as ground
#   truth is circular: the model defines what is anomalous and then we measure
#   how well it agrees with itself. This always gives trivially high P/R/F1
#   and provides no information about real security recall. We reserve true
#   labels for the controlled labeled-scenario probe set (Step 6).
# ---------------------------------------------------------------------------
print("=" * 60)
print(f"STEP 3: 80/20 train-test split (seed={RANDOM_STATE})")
print("=" * 60)

rng = np.random.default_rng(seed=RANDOM_STATE)
n_total   = X.shape[0]
n_train   = int(n_total * TRAIN_FRACTION)
n_test    = n_total - n_train

shuffled_idx = rng.permutation(n_total)
train_idx    = shuffled_idx[:n_train]
test_idx     = shuffled_idx[n_train:]

X_train = X[train_idx]
X_test  = X[test_idx]

print(f"  Total rows : {n_total:,}")
print(f"  Train rows : {n_train:,}  ({TRAIN_FRACTION:.0%})")
print(f"  Test  rows : {n_test:,}  ({1-TRAIN_FRACTION:.0%})\n")


# ---------------------------------------------------------------------------
# Step 4: Fit Isolation Forest on training set only
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 4: Training Isolation Forest (on 80% train set)")
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
model.fit(X_train)
train_time = time.time() - t1
print(f"  Training complete in {train_time:.1f}s\n")

# Sanity check on first 1000 training rows
sanity_scores = model.decision_function(X_train[:1000])
sanity_preds  = model.predict(X_train[:1000])
sanity_n_anom = int((sanity_preds == -1).sum())
print(f"  Sanity check (first 1000 train rows):")
print(f"    Anomalies    : {sanity_n_anom} ({sanity_n_anom/10:.1f}%)")
print(f"    Score range  : [{sanity_scores.min():.4f}, {sanity_scores.max():.4f}]")

joblib.dump(model, MODEL_PATH)
print(f"\n  Saved -> {MODEL_PATH}\n")


# ---------------------------------------------------------------------------
# Step 5: Evaluate on held-out test set (20%)
# ---------------------------------------------------------------------------
# Metrics collected here:
#   - Anomaly rate: what fraction of the test set the model flags
#   - Score distribution: min/max/mean/std/percentiles of decision_function
#   - Risk score distribution: how events bucket into Low/Moderate/High/Critical
#   - Inference throughput: events/second on the test set (batch)
#
# We deliberately do NOT compute P/R/F1 here — the test set has no
# external labels. See Step 6 for honest P/R/F1 via labeled scenarios.
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 5: Test-set evaluation (held-out 20%)")
print("=" * 60)

t2 = time.time()
test_scores = model.decision_function(X_test)
test_preds  = model.predict(X_test)
infer_time  = time.time() - t2
throughput  = n_test / infer_time

n_anomalies_test  = int((test_preds == -1).sum())
n_normal_test     = n_test - n_anomalies_test
test_anomaly_rate = 100.0 * n_anomalies_test / n_test

print(f"  Test set size    : {n_test:,}")
print(f"  Anomalies        : {n_anomalies_test:,}  ({test_anomaly_rate:.2f}%)")
print(f"  Normal           : {n_normal_test:,}  ({100-test_anomaly_rate:.2f}%)")
print(f"  Score min        : {test_scores.min():.4f}")
print(f"  Score max        : {test_scores.max():.4f}")
print(f"  Score mean       : {test_scores.mean():.4f}")
print(f"  Inference time   : {infer_time:.2f}s  ({throughput:,.0f} events/s)")

# Risk score distribution using the same base formula as the pipeline
# (base component only — we don't have severity/confidence for test rows)
def _base_risk(score: float) -> int:
    return max(0, min(60, int(round((-score + 0.05) * 300.0))))

base_risks = np.array([_base_risk(float(s)) for s in test_scores])
risk_buckets = [
    ("0-20 (Low)",      0,  20),
    ("21-40 (Moderate)",21, 40),
    ("41-60 (High)",    41, 60),
]
risk_counts: dict = {}
for label, lo, hi in risk_buckets:
    cnt = int(np.sum((base_risks >= lo) & (base_risks <= hi)))
    risk_counts[label] = cnt
    pct = 100.0 * cnt / n_test
    print(f"  Risk {label:22s}: {cnt:>8,}  ({pct:.2f}%)")


# ---------------------------------------------------------------------------
# Step 6: Honest P/R/F1 via labeled security scenarios
# ---------------------------------------------------------------------------
# This is a hand-crafted probe set of events with human-assigned labels.
# Ground truth: 1 = should be flagged as anomalous, 0 = should be normal.
#
# WHY this approach is valid:
#   - We have domain knowledge (AWS security expertise, MITRE ATT&CK) about
#     which event patterns are genuinely security-relevant.
#   - We test whether the model's anomaly score AGREES with that external
#     domain knowledge — this is true external validation, not circular.
#   - The probe set covers all 6 threat categories and normal variants.
#
# WHY we use score < THRESHOLD (not model.predict()) as our binary decision:
#   model.predict() uses the contamination-based internal cutoff. Using
#   ANOMALY_THRESHOLD gives the same binary decision the Lambda function
#   makes at runtime, so the P/R/F1 is operationally meaningful.
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 6: Labeled-scenario P/R/F1 evaluation")
print("=" * 60)
print(f"  Using threshold: {ANOMALY_THRESHOLD}  (same as production Lambda)\n")

# Each tuple: (event_name, hour, user_type, region, is_root, label, description)
# label=1: should be flagged as anomalous
# label=0: should be treated as normal
LABELED_SCENARIOS = [
    # ── Privilege Escalation ────────────────────────────────────────────────
    ("AttachUserPolicy",    2,  "Root",        "ap-southeast-2", 1, 1, "Root AttachUserPolicy 2am unusual region"),
    ("CreateAccessKey",     3,  "Root",        "us-west-2",      1, 1, "Root CreateAccessKey 3am"),
    ("AttachRolePolicy",    1,  "IAMUser",     "ap-southeast-2", 0, 1, "IAMUser AttachRolePolicy 1am unusual region"),
    ("PutUserPolicy",       4,  "Root",        "us-east-1",      1, 1, "Root PutUserPolicy 4am"),
    ("AddUserToGroup",     23,  "AssumedRole", "sa-east-1",      0, 1, "AssumedRole AddUserToGroup 11pm unusual region"),

    # ── Defense Evasion ────────────────────────────────────────────────     
    ("DeleteTrail",         3,  "Root",        "us-east-1",      1, 1, "Root DeleteTrail 3am"),
    ("StopLogging",         2,  "Root",        "us-west-2",      1, 1, "Root StopLogging 2am"),
    ("DeleteFlowLogs",      1,  "IAMUser",     "ap-southeast-2", 0, 1, "IAMUser DeleteFlowLogs 1am unusual region"),
    ("UpdateTrail",         4,  "Root",        "eu-west-1",      1, 1, "Root UpdateTrail 4am"),
    ("DeleteConfigRule",   23,  "AssumedRole", "ap-northeast-1", 0, 1, "AssumedRole DeleteConfigRule 11pm"),

    # ── Credential / Root anomaly ───────────────────────────────────────────
    ("GetConsoleOutput",   14,  "Root",        "us-east-1",      1, 1, "Root API call during business hours"),
    ("ListUsers",          10,  "Root",        "us-east-1",      1, 1, "Root ListUsers midday"),

    # ── Temporal / Off-hours anomaly ────────────────────────────────────────
    ("DescribeInstances",   2,  "IAMUser",     "us-east-1",      0, 1, "IAMUser Describe at 2am"),
    ("ListBuckets",         3,  "IAMUser",     "us-east-1",      0, 1, "IAMUser ListBuckets at 3am"),

    # ── Geographic anomaly ──────────────────────────────────────────────────
    ("DescribeInstances",  10,  "IAMUser",     "ap-southeast-2", 0, 1, "IAMUser normal event from unusual region"),
    ("CreateFunction20150331", 14, "IAMUser",  "sa-east-1",      0, 1, "IAMUser Lambda create unusual region"),

    # ── Normal events (should NOT be flagged) ───────────────────────────────
    ("ListBuckets",        10,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser ListBuckets 10am"),
    ("DescribeInstances",  14,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser DescribeInstances 2pm"),
    ("GetObject",          11,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser GetObject 11am"),
    ("PutObject",          13,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser PutObject 1pm"),
    ("DescribeSecurityGroups", 9,"IAMUser",    "us-east-1",      0, 0, "Normal: IAMUser DescribeSecurityGroups"),
    ("DescribeSubnets",    10,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser DescribeSubnets 10am"),
    ("AssumeRole",         10,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser AssumeRole 10am"),
    ("GetCallerIdentity",  12,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser GetCallerIdentity noon"),
    ("ListRoles",          11,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser ListRoles 11am"),
    ("DescribeVpcs",       15,  "AssumedRole", "us-east-1",      0, 0, "Normal: AssumedRole DescribeVpcs 3pm"),
    ("ListObjects",        10,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser ListObjects 10am"),
    ("DescribeImages",     14,  "IAMUser",     "us-east-1",      0, 0, "Normal: IAMUser DescribeImages 2pm"),
]

y_true_scenarios: list = []
y_pred_scenarios: list = []
scenario_results: list = []

print(f"  {'Scenario':<52} {'Score':>7}  {'Pred':>6}  {'Label':>5}  {'OK?':>4}")
print("  " + "-" * 78)

for (ev, hr, ut, rg, ir, true_label, desc) in LABELED_SCENARIOS:
    cat_df  = pd.DataFrame([[ev, ut, rg]], columns=CATEGORICAL_FEATURES)
    cat_enc = encoder.transform(cat_df)
    row     = np.array([[cat_enc[0, 0], hr, cat_enc[0, 1], cat_enc[0, 2], float(ir)]])
    score   = float(model.decision_function(row)[0])
    pred    = 1 if score < ANOMALY_THRESHOLD else 0
    match   = "Y" if pred == true_label else "N"

    y_true_scenarios.append(true_label)
    y_pred_scenarios.append(pred)
    scenario_results.append({
        "description":   desc,
        "event_name":    ev,
        "hour":          hr,
        "user_type":     ut,
        "region":        rg,
        "is_root":       ir,
        "anomaly_score": round(score, 6),
        "predicted":     pred,
        "expected":      true_label,
        "correct":       pred == true_label,
    })
    print(f"  {desc:<52} {score:>+7.4f}  {'ANOM' if pred else 'norm':>6}  {'ANOM' if true_label else 'norm':>5}  {match:>4}")

y_true_arr = np.array(y_true_scenarios)
y_pred_arr = np.array(y_pred_scenarios)

n_scenarios = len(y_true_scenarios)
n_correct   = int((y_true_arr == y_pred_arr).sum())
acc  = accuracy_score(y_true_arr, y_pred_arr)
prec = precision_score(y_true_arr, y_pred_arr, zero_division=0)
rec  = recall_score(y_true_arr, y_pred_arr, zero_division=0)
f1   = f1_score(y_true_arr, y_pred_arr, zero_division=0)

tp = int(((y_true_arr == 1) & (y_pred_arr == 1)).sum())
fp = int(((y_true_arr == 0) & (y_pred_arr == 1)).sum())
tn = int(((y_true_arr == 0) & (y_pred_arr == 0)).sum())
fn = int(((y_true_arr == 1) & (y_pred_arr == 0)).sum())

print()
print(f"  Scenarios  : {n_scenarios}  ({int(sum(y_true_arr))} anomalous, {int(sum(1-y_true_arr))} normal)")
print(f"  Correct    : {n_correct}/{n_scenarios}")
print(f"  Accuracy   : {acc:.4f}")
print(f"  Precision  : {prec:.4f}  (of flagged events, how many are truly anomalous)")
print(f"  Recall     : {rec:.4f}  (of truly anomalous events, how many were caught)")
print(f"  F1 Score   : {f1:.4f}")
print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")


# ---------------------------------------------------------------------------
# Step 7: Verify encoder + model round-trip (smoke test)
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 7: Round-trip verification (encoder + model reload)")
print("=" * 60)

enc_loaded   = joblib.load(ENCODER_PATH)
model_loaded = joblib.load(MODEL_PATH)

roundtrip_cases = [
    ("ListBuckets",        10, "IAMUser", "us-east-1",  "normal activity"),
    ("DeleteTrail",         3, "Root",    "us-east-1",  "high-risk: defense evasion"),
    ("CreateAccessKey",     2, "Root",    "us-west-2",  "high-risk: priv escalation"),
    ("UnknownEventXYZ",    14, "Unknown", "us-east-1",  "unseen event name -> -1"),
]

for event_name, hour, user_type, region, note in roundtrip_cases:
    cat_df  = pd.DataFrame([[event_name, user_type, region]], columns=CATEGORICAL_FEATURES)
    cat_enc = enc_loaded.transform(cat_df)
    is_root = 1 if user_type == "Root" else 0
    row     = np.array([[cat_enc[0, 0], hour, cat_enc[0, 1], cat_enc[0, 2], is_root]])
    score   = float(model_loaded.decision_function(row)[0])
    pred    = "ANOMALY" if model_loaded.predict(row)[0] == -1 else "normal"
    print(f"  [{pred:7s}] score={score:+.4f}  {event_name!r}  ({note})")


# ---------------------------------------------------------------------------
# Step 8: Save evaluation report (eval_report.json)
# ---------------------------------------------------------------------------
print("=" * 60)
print("STEP 8: Saving eval_report.json")
print("=" * 60)

report = {
    "model":             "IsolationForest",
    "n_estimators":      N_ESTIMATORS,
    "contamination":     CONTAMINATION,
    "random_state":      RANDOM_STATE,
    "anomaly_threshold": ANOMALY_THRESHOLD,

    "training": {
        "total_corpus_rows":  int(n_total),
        "train_rows":         int(n_train),
        "train_fraction":     TRAIN_FRACTION,
        "train_time_seconds": round(train_time, 2),
        "feature_names":      FEATURE_NAMES,
        "categorical_features": CATEGORICAL_FEATURES,
    },

    "test_set": {
        "test_rows":           int(n_test),
        "test_fraction":       round(1 - TRAIN_FRACTION, 2),
        "anomalies_flagged":   n_anomalies_test,
        "normal_events":       n_normal_test,
        "anomaly_rate_pct":    round(float(test_anomaly_rate), 4),
        "infer_time_seconds":  round(infer_time, 2),
        "throughput_events_per_sec": round(float(throughput)),
        "score_distribution": {
            "min":  round(float(test_scores.min()), 6),
            "max":  round(float(test_scores.max()), 6),
            "mean": round(float(test_scores.mean()), 6),
            "std":  round(float(test_scores.std()), 6),
            "p10":  round(float(np.percentile(test_scores, 10)), 6),
            "p25":  round(float(np.percentile(test_scores, 25)), 6),
            "p50":  round(float(np.percentile(test_scores, 50)), 6),
            "p75":  round(float(np.percentile(test_scores, 75)), 6),
            "p90":  round(float(np.percentile(test_scores, 90)), 6),
        },
        "risk_score_distribution": {k: v for k, v in risk_counts.items()},
        "evaluation_note": (
            "Test set has no external ground-truth labels. "
            "Anomaly rate, score distribution, and throughput are reported. "
            "P/R/F1 are NOT computed here to avoid circular evaluation."
        ),
    },

    "labeled_scenario_eval": {
        "n_scenarios":     n_scenarios,
        "n_anomalous":     int(sum(y_true_arr)),
        "n_normal":        int(sum(1 - y_true_arr)),
        "n_correct":       n_correct,
        "accuracy":        round(float(acc), 4),
        "precision":       round(float(prec), 4),
        "recall":          round(float(rec), 4),
        "f1_score":        round(float(f1), 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "evaluation_method": (
            "Hand-crafted security scenarios with human-assigned ground truth labels. "
            f"Decision boundary: anomaly_score < {ANOMALY_THRESHOLD} (same as production Lambda). "
            "This is the only honest P/R/F1 for an unsupervised model: external domain knowledge "
            "labels are used, not contamination-derived surrogate labels."
        ),
        "scenarios": scenario_results,
    },
}

with open(EVAL_REPORT_PATH, "w") as f:
    _json.dump(report, f, indent=2)

print(f"  Saved -> {EVAL_REPORT_PATH}")
print()
print("All steps complete. Files ready:")
print(f"  encoder.pkl      ({ENCODER_PATH.stat().st_size / 1024:.1f} KB)")
print(f"  model.pkl        ({MODEL_PATH.stat().st_size / 1024:.1f} KB)")
print(f"  eval_report.json")
print()
print("Summary:")
print(f"  Train set      : {n_train:,} rows  (80%)")
print(f"  Test set       : {n_test:,} rows   (20%)")
print(f"  Test anomaly % : {test_anomaly_rate:.2f}%")
print(f"  Scenario F1    : {f1:.4f}  (on {n_scenarios} labeled probes)")
print(f"  Throughput     : {throughput:,.0f} events/s")

