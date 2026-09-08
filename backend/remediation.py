"""
remediation.py
==============
Controlled remediation: writes results to DynamoDB and (only when ENFORCE_MODE
is explicitly enabled AND all safety gates pass) applies the IAM policy.

Safety architecture:
  SIMULATION_MODE=True (default) -> DynamoDB write only, status=SIMULATED
  ENFORCE_MODE=True              -> live iam.put_user_policy() after all gates
  PROTECTED_PRINCIPALS           -> always blocked from enforcement
  validation_status BLOCKED      -> never enforced
  requires_approval=True         -> status=PENDING_APPROVAL, not enforced until
                                   human sets status=APPROVED in DynamoDB

Rollback: all attached policy names are stored. remediation.rollback(event_id)
calls iam.delete_user_policy() using stored policy_name + target_arn.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import ClientError

from config import (
    DYNAMODB_TABLE,
    DYNAMODB_REGION,
    SNS_TOPIC_ARN,
    SNS_REGION,
    SIMULATION_MODE,
    ENFORCE_MODE,
    ANOMALY_SCORE_THRESHOLD,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def _get_table():
    db = boto3.resource("dynamodb", region_name=DYNAMODB_REGION)
    return db.Table(DYNAMODB_TABLE)


def _to_decimal(v):
    """Convert float to Decimal for DynamoDB (boto3 requirement)."""
    if isinstance(v, float):
        return Decimal(str(round(v, 6)))
    return v


def _sanitize_for_dynamo(obj: Any) -> Any:
    """Recursively replace floats with Decimal for DynamoDB storage."""
    if isinstance(obj, dict):
        return {k: _sanitize_for_dynamo(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_dynamo(i) for i in obj]
    if isinstance(obj, float):
        return _to_decimal(obj)
    return obj


# ---------------------------------------------------------------------------
# Main remediation entry point
# ---------------------------------------------------------------------------

def apply_remediation(
    score_result:      dict[str, Any],
    xai_result:        dict[str, Any],
    threat_result:     dict[str, Any],
    policy_result:     dict[str, Any],
    validation_result: dict[str, Any],
    raw_event:         dict[str, Any],
    event_id:          str,
) -> dict[str, Any]:
    """
    Determine remediation status, write to DynamoDB, and optionally enforce.

    Returns a dict summarising the action taken.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Determine remediation status
    status = _determine_status(policy_result, validation_result)

    # Build the full DynamoDB item
    event_detail = raw_event.get("detail", raw_event)
    item = {
        # --- Identity ---
        "eventId":       event_id,
        "timestamp":     event_detail.get("eventTime", now),
        "ingested_at":   now,

        # --- Raw event fields ---
        "eventName":     score_result["features"].get("eventName", "Unknown"),
        "eventSource":   event_detail.get("eventSource", "Unknown"),
        "awsRegion":     score_result["features"].get("awsRegion", "Unknown"),
        "userType":      score_result["features"].get("userIdentitytype", "Unknown"),
        "isRoot":        score_result["features"].get("isRoot", 0),
        "sourceIP":      event_detail.get("sourceIPAddress", "Unknown"),
        "userIdentityarn": policy_result.get("target_arn", "Unknown"),

        # --- ML output ---
        "isAnomaly":     score_result["is_anomaly"],
        "anomalyScore":  _to_decimal(score_result["anomaly_score"]),
        "riskScore":     _anomaly_to_risk_score(score_result["anomaly_score"]),
        "severity":      threat_result.get("severity", "Unknown"),

        # --- XAI ---
        "xai_top_feature":           xai_result.get("top_feature", ""),
        "xai_top_shap":              _to_decimal(xai_result.get("top_shap_value", 0.0)),
        "xai_attribution_confidence": _to_decimal(xai_result.get("attribution_confidence", 0.0)),
        "xai_all_shap":              _sanitize_for_dynamo(xai_result.get("shap_values", {})),
        "xai_is_uncertain":          xai_result.get("is_uncertain", True),

        # --- Threat classification ---
        "threat_category":   threat_result.get("threat_category", "UNCERTAIN"),
        "threat_label":      threat_result.get("label", ""),
        "mitre_technique":   threat_result.get("mitre_technique", ""),
        "mitre_name":        threat_result.get("mitre_name", ""),
        "confidence_level":  threat_result.get("confidence_level", "Low"),
        "threat_rationale":  threat_result.get("rationale", ""),

        # --- IAM policy ---
        "policy_name":           policy_result.get("policy_name", ""),
        "policy_json":           policy_result.get("policy_json", ""),
        "policy_target_arn":     policy_result.get("target_arn", ""),
        "policy_principal_type": policy_result.get("principal_type", ""),
        "enforcement_eligible":  policy_result.get("enforcement_eligible", False),
        "policy_skip_reason":    policy_result.get("skip_reason") or "",

        # --- Access Analyzer ---
        "validation_status":   validation_result.get("validation_status", ""),
        "validation_proceed":  validation_result.get("proceed", False),
        "validation_findings": json.dumps(
            validation_result.get("findings_summary", [])
        ),

        # --- Remediation status ---
        "remediation_status": status,
    }

    # Write to DynamoDB
    try:
        _get_table().put_item(Item=item)
        logger.info("DynamoDB write OK: eventId=%s status=%s", event_id, status)
    except ClientError as e:
        logger.error("DynamoDB write failed: %s", e)

    # Send SNS alert for high-severity anomalies
    if threat_result.get("severity") in ("Critical", "High") and SNS_TOPIC_ARN:
        _send_sns_alert(item)

    # Enforce if all gates pass
    enforced = False
    if status == "PENDING_APPROVAL":
        logger.info("Remediation requires human approval: eventId=%s", event_id)
    elif status == "APPROVED_FOR_ENFORCEMENT" and ENFORCE_MODE:
        enforced = _enforce_policy(policy_result, event_id)

    return {
        "event_id":           event_id,
        "remediation_status": status,
        "enforced":           enforced,
        "simulation_mode":    SIMULATION_MODE,
    }


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def _enforce_policy(policy_result: dict, event_id: str) -> bool:
    """Apply the IAM inline policy to the target principal."""
    if SIMULATION_MODE:
        logger.info("SIMULATION_MODE=True — skipping enforcement for eventId=%s", event_id)
        return False

    if not policy_result.get("enforcement_eligible"):
        logger.info("enforcement_eligible=False — skipping: %s", policy_result.get("skip_reason"))
        return False

    target_arn  = policy_result.get("target_arn", "")
    policy_name = policy_result.get("policy_name", "")
    policy_json = policy_result.get("policy_json", "")
    principal   = policy_result.get("principal_type", "")

    try:
        iam = boto3.client("iam")
        if principal == "IAMUser":
            user_name = target_arn.split("/")[-1]
            iam.put_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
                PolicyDocument=policy_json,
            )
        elif principal == "AssumedRole":
            role_name = target_arn.split("/")[-2]
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=policy_json,
            )
        else:
            logger.warning("Unsupported principal type for enforcement: %s", principal)
            return False

        logger.info("Policy enforced: %s on %s", policy_name, target_arn)
        return True

    except ClientError as e:
        logger.error("IAM enforcement failed: %s", e)
        return False


def rollback(event_id_prefix: str) -> bool:
    """
    Remove an attached CloudGuard inline policy by event_id prefix.
    Looks up the DynamoDB item to find policy_name and target_arn.
    """
    try:
        table  = _get_table()
        result = table.get_item(Key={"eventId": event_id_prefix})
        item   = result.get("Item")
        if not item:
            logger.error("Rollback: no item found for eventId=%s", event_id_prefix)
            return False

        iam         = boto3.client("iam")
        policy_name = item.get("policy_name", "")
        target_arn  = item.get("policy_target_arn", "")
        principal   = item.get("policy_principal_type", "")

        if principal == "IAMUser":
            user_name = target_arn.split("/")[-1]
            iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        elif principal == "AssumedRole":
            role_name = target_arn.split("/")[-2]
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        else:
            logger.error("Cannot rollback: unsupported principal type %s", principal)
            return False

        # Update DynamoDB status
        table.update_item(
            Key={"eventId": event_id_prefix},
            UpdateExpression="SET remediation_status = :s",
            ExpressionAttributeValues={":s": "ROLLED_BACK"},
        )
        logger.info("Rollback complete: %s / %s", policy_name, target_arn)
        return True

    except ClientError as e:
        logger.error("Rollback failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _determine_status(
    policy_result: dict,
    validation_result: dict,
) -> str:
    if SIMULATION_MODE:
        return "SIMULATED"
    if not validation_result.get("proceed"):
        return "BLOCKED"
    if validation_result.get("requires_approval"):
        return "PENDING_APPROVAL"
    if not policy_result.get("enforcement_eligible"):
        return "SIMULATED"  # enforcement not applicable (root / protected / uncertain)
    return "APPROVED_FOR_ENFORCEMENT"


def _anomaly_to_risk_score(anomaly_score: float) -> int:
    """
    Convert IsolationForest decision_function score to a 0–100 risk integer.
    Score range in practice: [-0.15, +0.25]. Negative = anomalous.
    """
    # Normalise: flip sign, clamp, scale to 0–100
    risk = max(0, min(100, int((-anomaly_score + 0.05) * 400)))
    return risk


def _send_sns_alert(item: dict) -> None:
    try:
        sns = boto3.client("sns", region_name=SNS_REGION)
        subject = f"CloudGuard Alert: {item['threat_label']} — {item['eventName']}"
        body = (
            f"Threat Category : {item['threat_label']}\n"
            f"MITRE Technique : {item['mitre_technique']} — {item['mitre_name']}\n"
            f"Event           : {item['eventName']}\n"
            f"Region          : {item['awsRegion']}\n"
            f"Anomaly Score   : {item['anomalyScore']}\n"
            f"Risk Score      : {item['riskScore']}\n"
            f"Top XAI Feature : {item['xai_top_feature']} (SHAP={item['xai_top_shap']})\n"
            f"Rationale       : {item['threat_rationale']}\n"
            f"Policy          : {item['policy_name']}\n"
            f"Status          : {item['remediation_status']}\n"
        )
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)
        logger.info("SNS alert sent: %s", subject)
    except ClientError as e:
        logger.warning("SNS publish failed: %s", e)
