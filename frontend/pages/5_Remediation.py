"""
5_Remediation.py
================
Human-in-the-loop remediation approval queue.
Shows kanban-style status summary, policy diff, validation badges,
and approve/reject actions.
All existing update_remediation_status logic preserved.
"""
import json
import streamlit as st
from utils import (
  inject_css,
  load_remediation_queue,
  load_xai_data,
  update_remediation_status,
  color_status,
  render_metric_card,
  render_badge,
)
st.set_page_config(page_title="Remediation — CloudGuard", layout="wide")
inject_css()
st.markdown("## Remediation")
st.markdown('<div class="cg-callout cg-callout-info">'
  '[Security] All policies operate in <strong>SIMULATION_MODE</strong> by default — no IAM changes are made '
  'until explicitly approved here and <code>ENFORCE_MODE=true</code> is set in the Lambda environment.'
  '</div>', unsafe_allow_html=True)
# ── Load queue ────────────────────────────────────────────────────────────────
df = load_remediation_queue()
if df.empty:
  st.markdown(
    '<div class="cg-callout cg-callout-info">'
    'No items are currently in the remediation queue. '
    'Items appear here when the CloudGuard Lambda processes real CloudTrail events '
    'through the full 8-stage pipeline and stores results in DynamoDB. '
    'Use <strong>Live Simulation</strong> to run the pipeline manually; results will '
    'appear here if your Lambda is connected to DynamoDB.'
    '</div>',
    unsafe_allow_html=True,
  )
  st.markdown(
    '<div class="cg-section-header">Implemented Remediation Flow</div>',
    unsafe_allow_html=True,
  )
  import pandas as pd
  _flow = [
    ("1", "Threat Detected",         "Isolation Forest flags anomaly_score < −0.02"),
    ("2", "Threat Classified",        "SHAP top feature → category (e.g. PRIVILEGE_ESCALATION, Critical)"),
    ("3", "MITRE ATT&CK Mapped",      "e.g. T1078 / T1098 — Valid Accounts / Account Manipulation"),
    ("4", "IAM Deny Policy Generated","iam_generator.generate_policy() → least-privilege Deny statement"),
    ("5", "Access Analyzer Validated","policy_validator.validate_policy() → CLEAN / WARNING / BLOCKED"),
    ("6", "Remediation Decision",      "remediation.apply_remediation() → SIMULATED | PENDING_APPROVAL | BLOCKED | ALERT_ONLY"),
    ("7", "Logged to DynamoDB + SNS",  "Full event record with all stage outputs stored; SNS alert published"),
  ]
  st.dataframe(
    pd.DataFrame(_flow, columns=["Step", "Stage", "Detail"]),
    use_container_width=True, hide_index=True,
  )
  st.markdown(
    '<div class="cg-callout cg-callout-warn">'
    '<strong>SIMULATION_MODE: true</strong> — no IAM policies are ever attached in the current configuration. '
    'All remediation actions are logged as SIMULATED. '
    'Set <code>ENFORCE_MODE=true</code> in the Lambda environment to enable real enforcement.'
    '</div>',
    unsafe_allow_html=True,
  )
  st.stop()

else:
  # ── Kanban-style Status Summary ───────────────────────────────────────────
  st.markdown('<div class="cg-section-header">Queue Status Overview</div>', unsafe_allow_html=True)
  total_pending  = len(df)
  simulated    = int((df["remediation_status"] == "SIMULATED").sum())    if "remediation_status" in df.columns else 0
  needs_approval = int((df["remediation_status"] == "PENDING_APPROVAL").sum()) if "remediation_status" in df.columns else 0
  approved    = int((df["remediation_status"] == "APPROVED_FOR_ENFORCEMENT").sum()) if "remediation_status" in df.columns else 0
  blocked     = int((df["remediation_status"] == "BLOCKED").sum())     if "remediation_status" in df.columns else 0
  k1, k2, k3, k4, k5 = st.columns(5)
  with k1:
    st.markdown(render_metric_card("Total Pending",   f"{total_pending}", "accent"), unsafe_allow_html=True)
  with k2:
    st.markdown(render_metric_card("Simulated",     f"{simulated}",   "purple"), unsafe_allow_html=True)
  with k3:
    st.markdown(render_metric_card("Needs Approval",  f"{needs_approval}","warning"), unsafe_allow_html=True)
  with k4:
    st.markdown(render_metric_card("Approved",     f"{approved}",   "success"), unsafe_allow_html=True)
  with k5:
    st.markdown(render_metric_card("Blocked",      f"{blocked}",    "critical"), unsafe_allow_html=True)
  st.divider()
  # ── Queue Table ───────────────────────────────────────────────────────────
  st.markdown('<div class="cg-section-header">Pending Remediation Items</div>', unsafe_allow_html=True)
  DISPLAY_COLS = [c for c in [
    "eventId", "eventName", "awsRegion", "severity",
    "threat_label", "mitre_technique", "confidence_level",
    "policy_name", "validation_status", "enforcement_eligible",
    "remediation_status", "timestamp",
  ] if c in df.columns]
  display_sorted = (
    df[DISPLAY_COLS].sort_values("timestamp", ascending=False)
    if "timestamp" in df.columns else df[DISPLAY_COLS]
  )
  st.dataframe(
    display_sorted.style.map(color_status, subset=["remediation_status"])
    if "remediation_status" in display_sorted.columns else display_sorted,
    use_container_width=True,
  )
  st.divider()
  # ── Per-item Review ───────────────────────────────────────────────────────
  st.markdown('<div class="cg-section-header">Review & Approve / Reject</div>', unsafe_allow_html=True)
  if "eventId" not in df.columns:
    st.error("DynamoDB items are missing the `eventId` primary key — cannot update.")
    st.stop()
  def _item_label(row) -> str:
    name = row.get("eventName", "?")
    eid = str(row.get("eventId", ""))[:8]
    cat = row.get("threat_label", row.get("threat_category", ""))
    return f"{name} [{cat}] — {eid}"
  item_labels  = df.apply(_item_label, axis=1).tolist()
  sSelected_label = st.selectbox("Select item to Review", item_labels, key="rem_selector")
  sel_idx = item_labels.index(sSelected_label)
  sel_row = df.iloc[sel_idx]
  # ── Detail Panel ──────────────────────────────────────────────────────────
  with st.container():
    dc1, dc2 = st.columns(2)
    with dc1:
      st.markdown("**Threat Information**")
      st.write("**Event Name:**",    sel_row.get("eventName", "Unknown"))
      st.write("**Region:**",      sel_row.get("awsRegion", sel_row.get("region", "Unknown")))
      st.write("**Threat Category:**", sel_row.get("threat_label", "Unknown"))
      st.write("**MITRE Technique:**", sel_row.get("mitre_technique", "N/A"))
      st.write("**Confidence:**",    sel_row.get("confidence_level", "Low"))
      st.write("**Severity:**",     sel_row.get("severity", "Unknown"))
    with dc2:
      st.markdown("**Remediation Information**")
      st.write("**Current Status:**",   sel_row.get("remediation_status", "Unknown"))
      st.write("**Validation:**",     sel_row.get("validation_status", "N/A"))
      st.write("**Enforcement Eligible:**","Yes" if sel_row.get("enforcement_eligible") else "No")
      st.write("**Target AN:**",     sel_row.get("policy_target_arn", "N/A"))
      st.write("**Policy Name:**",     sel_row.get("policy_name", "N/A"))
      
      from utils import render_risk_gauge
      st.markdown(render_risk_gauge(int(sel_row.get("riskScore", 0))), unsafe_allow_html=True)
    # Rationale
    if sel_row.get("threat_rationale"):
      with st.expander("📝 Threat Rationale"):
        st.write(sel_row.get("threat_rationale"))
    # ── Side-by-side Policy Diff ──────────────────────────────────────────
    _pjson = sel_row.get("policy_json", "") or ""
    _pjson = str(_pjson).strip()
    if _pjson and _pjson not in ("nan", "None", "{}"):
      st.markdown("**IAM Policy — Before vs. After Remediation**")
      diff_l, diff_r = st.columns(2)
      with diff_l:
        st.markdown("*Before: No Deny policy (default allow)*")
        st.code(
          json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
              "Note": "No CloudGuard deny policy attached — "
                  "principal has full permissions as defined by allow policies."
            }]
          }, indent=2),
          language="json",
        )
      with diff_r:
        st.markdown("*After: Generated least-privilege Deny policy*")
        try:
          pretty = json.dumps(json.loads(_pjson), indent=2)
        except Exception:
          pretty = _pjson
        st.code(pretty, language="json")
    # ── Validation Badge Panel ────────────────────────────────────────────
    val_s = str(sel_row.get("validation_status", ""))
    if val_s:
      VAL_VARIANT = {
        "CLEAN":      ("success", "CLEAN — Access Analyzer found no issues"),
        "SUGGESTION_ONLY": ("success", "CLEAN — Suggestions only (informational)"),
        "WARNING_PRESENT": ("warning", "Warning: WARNING — Requires human approval before enforcement"),
        "BLOCKED":     ("critical","BLOCKED — Security finding prevents enforcement"),
        "ERROR":      ("critical","ERROR — Malformed policy, never enforce"),
      }
      v_variant, v_label = VAL_VARIANT.get(val_s, ("info", val_s))
      st.markdown(
        f'<div class="cg-callout cg-callout-{v_variant}"><strong>Access Analyzer: {v_label}</strong></div>',
        unsafe_allow_html=True,
      )
    _vf = sel_row.get("validation_findings", "") or ""
    _vf = str(_vf).strip()
    if _vf and _vf not in ("nan", "None", "[]", ""):
      with st.expander("Access Analyzer Findings"):
        try:
          st.json(json.loads(_vf))
        except Exception:
          st.write(_vf)
  st.divider()
  # ── Warnings before action ────────────────────────────────────────────────
  if not sel_row.get("enforcement_eligible"):
    st.markdown('<div class="cg-callout cg-callout-warn">Warning: This policy is <strong>not enforcement-eligible</strong> '
      '(root account, protected principal, or uncertain classification). '
      'Approving will update the record status only — no IAM call will be made.</div>', unsafe_allow_html=True)
  if sel_row.get("validation_status") in ("BLOCKED", "ERROR", "SECURITY_WARNING"):
    st.markdown('<div class="cg-callout cg-callout-error">Access Analyzer flagged this policy with a blocking finding. '
      'Approving is recorded but the Lambda enforcement gate will reject it.</div>', unsafe_allow_html=True)
  # ── Approve / Reject ──────────────────────────────────────────────────────
  event_id = str(sel_row.get("eventId", ""))
  b1, b2, _ = st.columns([1, 1, 4])
  with b1:
    if st.button("Approve", key=f"approve_{event_id}", type="primary"):
      ok = update_remediation_status(event_id, "APPROVED_FOR_ENFORCEMENT")
      if ok:
        st.success(f"Approved: {event_id[:8]}. Status → APPROVED_FOR_ENFORCEMENT.")
        st.rerun()
      else:
        st.error("Failed to update DynamoDB — check AWS credentials and table name.")
  with b2:
    if st.button("Reject", key=f"reject_{event_id}"):
      ok = update_remediation_status(event_id, "BLOCKED")
      if ok:
        st.warning(f"Rejected: {event_id[:8]}. Status → BLOCKED.")
        st.rerun()
      else:
        st.error("Failed to update DynamoDB — check AWS credentials and table name.")
st.divider()
# ── Status Reference Legend ───────────────────────────────────────────────────
st.markdown('<div class="cg-section-header">Status Reference</div>')
st.markdown("""
| Status | Meaning |
|---|---|
| `SIMULATED` | Policy generated and validated — no IAM change made |
| `PENDING_APPROVAL` | Requires human approval before enforcement consideration |
| `APPROVED_FOR_ENFORCEMENT` | Operator approved — Lambda will enforce on next invocation if `ENFORCE_MODE=true` |
| `BLOCKED` | Policy rejected by operator or Access Analyzer — will never be enforced |
| `ENFORCED` | IAM inline policy has been attached to the target principal |
| `ROLLED_BACK` | Previously enforced policy has been removed |
""")