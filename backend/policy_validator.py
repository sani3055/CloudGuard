"""
policy_validator.py
===================
Validates a generated IAM policy through AWS IAM Access Analyzer
before any enforcement consideration.

Correct boto3 API:
  client.validate_policy(policyDocument=str, policyType='IDENTITY_POLICY')

Finding type handling (from the audit):
  ERROR            -> Block: invalid syntax. Never proceed.
  SECURITY_WARNING -> Block: security implications. Require human review.
  WARNING          -> Allow with flag: log and store, require human approval.
  SUGGESTION       -> Allow: informational only.
  No findings      -> Full green path.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from config import (
    ACCESS_ANALYZER_REGION,
    BLOCKING_FINDING_TYPES,
    ALLOWED_WITH_WARNING_TYPES,
    SUGGESTION_TYPES,
)

logger = logging.getLogger(__name__)


def validate_policy(
    policy_json: str,
    policy_type: str = "IDENTITY_POLICY",
) -> dict[str, Any]:
    """
    Validate an IAM policy document using AWS IAM Access Analyzer.

    Parameters
    ----------
    policy_json : str
        The IAM policy as a JSON string.
    policy_type : str
        "IDENTITY_POLICY" (default) or "RESOURCE_POLICY".

    Returns
    -------
    dict with keys:
        proceed              : bool   — True if policy may advance to controlled response
        validation_status    : str    — CLEAN | WARNING_PRESENT | BLOCKED | ERROR
        requires_approval    : bool   — True if WARNING findings present
        blocking_reason      : str | None
        findings_summary     : list[dict]  — condensed findings
        raw_findings         : list[dict]  — full Access Analyzer response
    """
    # Validate JSON is parseable before making API call
    try:
        json.loads(policy_json)
    except json.JSONDecodeError as e:
        logger.error("Policy JSON is malformed: %s", e)
        return {
            "proceed":           False,
            "validation_status": "ERROR",
            "requires_approval": False,
            "blocking_reason":   f"Malformed policy JSON: {e}",
            "findings_summary":  [],
            "raw_findings":      [],
        }

    try:
        client = boto3.client("accessanalyzer", region_name=ACCESS_ANALYZER_REGION)
        response = client.validate_policy(
            policyDocument=policy_json,
            policyType=policy_type,   # REQUIRED parameter — previous plan omitted this
        )
        findings = response.get("findings", [])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg  = e.response["Error"]["Message"]
        logger.error("Access Analyzer API error: %s — %s", code, msg)
        return {
            "proceed":           False,
            "validation_status": "ERROR",
            "requires_approval": False,
            "blocking_reason":   f"Access Analyzer API error: {code} — {msg}",
            "findings_summary":  [],
            "raw_findings":      [],
        }

    # Categorise findings
    blocking_findings   = [f for f in findings if f.get("findingType") in BLOCKING_FINDING_TYPES]
    warning_findings    = [f for f in findings if f.get("findingType") in ALLOWED_WITH_WARNING_TYPES]
    suggestion_findings = [f for f in findings if f.get("findingType") in SUGGESTION_TYPES]

    findings_summary = [
        {
            "findingType":  f.get("findingType"),
            "issueCode":    f.get("issueCode"),
            "learnMoreLink": f.get("learnMoreLink"),
            "findingDetails": f.get("findingDetails", "")[:200],  # truncate for DynamoDB
        }
        for f in findings
    ]

    if blocking_findings:
        types_found = list({f["findingType"] for f in blocking_findings})
        reason = (
            f"Policy blocked due to {types_found} findings: "
            + "; ".join(f.get("issueCode", "") for f in blocking_findings[:3])
        )
        logger.warning("validate_policy BLOCKED: %s", reason)
        return {
            "proceed":           False,
            "validation_status": "BLOCKED",
            "requires_approval": False,
            "blocking_reason":   reason,
            "findings_summary":  findings_summary,
            "raw_findings":      findings,
        }

    if warning_findings:
        logger.info("validate_policy WARNING_PRESENT (%d warnings)", len(warning_findings))
        return {
            "proceed":           True,
            "validation_status": "WARNING_PRESENT",
            "requires_approval": True,   # human approval needed before enforcement
            "blocking_reason":   None,
            "findings_summary":  findings_summary,
            "raw_findings":      findings,
        }

    # SUGGESTION findings are purely informational — proceed without approval
    logger.info("validate_policy CLEAN/SUGGESTION (suggestions=%d)", len(suggestion_findings))
    return {
        "proceed":           True,
        "validation_status": "CLEAN" if not suggestion_findings else "SUGGESTION_ONLY",
        "requires_approval": False,   # SUGGESTION does NOT require approval
        "blocking_reason":   None,
        "findings_summary":  findings_summary,
        "raw_findings":      findings,
    }
