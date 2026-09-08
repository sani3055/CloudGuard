"""
feature_contract.py
====================
The single source of truth for feature extraction and encoding in CloudGuard.

This module defines:
  - The canonical FEATURE_NAMES list (training order)
  - The complete category vocabularies (from dec12_18features.csv, 1.93M rows)
  - extract_features()  — raw CloudTrail JSON  →  named feature dict
  - build_dataframe()   — feature dict         →  single-row pd.DataFrame

CRITICAL RULE:
  Both train.py (training time) and lambda_function.py (inference time) must
  import and use ONLY this module for feature extraction and encoding.
  Never re-implement feature logic elsewhere.

Encoding is handled by a fitted sklearn OrdinalEncoder saved as encoder.pkl.
The encoder must be loaded once and reused — it is NOT created here.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import pandas as pd

# ---------------------------------------------------------------------------
# 1. Canonical feature list — order is fixed and must never change
#    after encoder.pkl is created.
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    "eventName",        # API call name (categorical)
    "hour",             # UTC hour of the event (0–23, integer)
    "userIdentitytype", # IAM principal type (categorical)
    "awsRegion",        # AWS region of the API call (categorical)
    "isRoot",           # 1 if userIdentitytype == "Root", else 0 (binary)
]

# ---------------------------------------------------------------------------
# 2. Categorical vocabularies
#    Sourced exhaustively from dec12_18features.csv (1,939,207 rows).
#    These are used to initialise the OrdinalEncoder in train.py so that the
#    encoder never encounters "unknown" values from the training data itself.
#    At inference time, unseen values are handled by unknown_value=-1.
# ---------------------------------------------------------------------------

# 1,242 unique event names from the real dataset.
# Stored as a sorted list so OrdinalEncoder categories are deterministic.
KNOWN_EVENT_NAMES: list[str] = sorted([
    "AcceptHandshake", "AcceptVpcPeeringConnection", "AddClientIDToOpenIDConnectProvider",
    "AddLayerVersionPermission", "AddPermission", "AddRoleToInstanceProfile",
    "AddUserToGroup", "ApplySecurityGroupsToLoadBalancer", "AssignPrivateIpAddresses",
    "AssociateAddress", "AssociateDhcpOptions", "AssociateIamInstanceProfile",
    "AssociateRouteTable", "AssociateSubnetCidrBlock", "AssociateVpcCidrBlock",
    "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
    "AttachGroupPolicy", "AttachInternetGateway", "AttachLoadBalancerToSubnets",
    "AttachNetworkInterface", "AttachRolePolicy", "AttachUserPolicy",
    "AttachVolume", "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress",
    "BatchCheckLayerAvailability", "BatchGetItem", "BatchWriteItem",
    "CancelExportTask", "CancelImportTask", "CancelKeyDeletion", "CancelSpotFleetRequests",
    "CancelSpotInstanceRequests", "ChangePassword", "CheckDnsAvailability",
    "CopyImage", "CopyObject", "CopySnapshot",
    "CreateAccessKey", "CreateAccountAlias", "CreateAlarm",
    "CreateAutoScalingGroup", "CreateBucket", "CreateCacheCluster",
    "CreateCapacityProvider", "CreateCluster", "CreateCustomerGateway",
    "CreateDBCluster", "CreateDBClusterSnapshot", "CreateDBInstance",
    "CreateDBInstanceReadReplica", "CreateDBSnapshot", "CreateDBSubnetGroup",
    "CreateDefaultSubnet", "CreateDefaultVpc", "CreateDeployment",
    "CreateDeploymentGroup", "CreateDhcpOptions", "CreateDistribution",
    "CreateDomain", "CreateEgressOnlyInternetGateway", "CreateElasticsearchDomain",
    "CreateEventBus", "CreateEventSourceMapping", "CreateFlowLogs",
    "CreateFunction20150331", "CreateFunction20201101",
    "CreateGroup", "CreateImage", "CreateInstanceProfile",
    "CreateInternetGateway", "CreateInvalidation", "CreateKeyPair",
    "CreateLaunchTemplate", "CreateLoadBalancer", "CreateManagedAccount",
    "CreateNatGateway", "CreateNetworkAcl", "CreateNetworkAclEntry",
    "CreateNetworkInterface", "CreateOrganization", "CreateOrganizationalUnit",
    "CreatePolicy", "CreatePolicyVersion", "CreateQueue",
    "CreateRole", "CreateRoute", "CreateRouteTable",
    "CreateSAMLProvider", "CreateSecret", "CreateSecurityGroup",
    "CreateSnapshot", "CreateStage", "CreateSubnet",
    "CreateTable", "CreateTags", "CreateTargetGroup",
    "CreateTopic", "CreateTrail", "CreateUser",
    "CreateVolume", "CreateVpc", "CreateVpcEndpoint",
    "CreateVpcPeeringConnection", "CreateVpnConnection", "CreateVpnGateway",
    "DecryptSecret", "DeleteAccessKey", "DeleteAccountAlias",
    "DeleteAlarm", "DeleteAutoScalingGroup", "DeleteBucket",
    "DeleteBucketPolicy", "DeleteCacheCluster", "DeleteCertificate",
    "DeleteCluster", "DeleteDBCluster", "DeleteDBInstance",
    "DeleteDBSnapshot", "DeleteDBSubnetGroup", "DeleteDeploymentGroup",
    "DeleteDhcpOptions", "DeleteDistribution", "DeleteDomain",
    "DeleteElasticsearchDomain", "DeleteEventBus", "DeleteEventSourceMapping",
    "DeleteFlowLogs", "DeleteFunction20150331", "DeleteGroup",
    "DeleteImage", "DeleteInstanceProfile", "DeleteInternetGateway",
    "DeleteKeyPair", "DeleteLaunchTemplate", "DeleteLoadBalancer",
    "DeleteNatGateway", "DeleteNetworkAcl", "DeleteNetworkAclEntry",
    "DeleteNetworkInterface", "DeleteOrganizationalUnit", "DeletePolicy",
    "DeletePolicyVersion", "DeleteQueue", "DeleteRole",
    "DeleteRolePolicy", "DeleteRouteTable", "DeleteSAMLProvider",
    "DeleteSecret", "DeleteSecurityGroup", "DeleteSnapshot",
    "DeleteSubnet", "DeleteTable", "DeleteTags",
    "DeleteTargetGroup", "DeleteTopic", "DeleteTrail",
    "DeleteUser", "DeleteUserPolicy", "DeleteVolume",
    "DeleteVpc", "DeleteVpcEndpoints", "DeleteVpcPeeringConnection",
    "DeleteVpnConnection", "DeleteVpnGateway", "DeregisterInstancesFromLoadBalancer",
    "DeregisterTargets", "DescribeAccountAttributes", "DescribeAccountLimits",
    "DescribeAddresses", "DescribeAlarms", "DescribeAutoScalingGroups",
    "DescribeAutoScalingInstances", "DescribeAvailabilityZones", "DescribeBucketReplication",
    "DescribeCacheClusters", "DescribeCertificate", "DescribeClassicLinkInstances",
    "DescribeCluster", "DescribeClusters", "DescribeContainerInstances",
    "DescribeDBClusters", "DescribeDBEngineVersions", "DescribeDBInstances",
    "DescribeDBParameterGroups", "DescribeDBParameters", "DescribeDBSnapshots",
    "DescribeDBSubnetGroups", "DescribeDhcpOptions", "DescribeElasticsearchDomains",
    "DescribeEvents", "DescribeFlowLogs", "DescribeImages",
    "DescribeInstanceAttribute", "DescribeInstanceCreditSpecifications", "DescribeInstanceStatus",
    "DescribeInstances", "DescribeInternetGateways", "DescribeKeyPairs",
    "DescribeLaunchTemplates", "DescribeListeners", "DescribeLoadBalancerAttributes",
    "DescribeLoadBalancerPolicies", "DescribeLoadBalancers", "DescribeNatGateways",
    "DescribeNetworkAcls", "DescribeNetworkInterfaces", "DescribeOrganization",
    "DescribeOrganizationalUnits", "DescribeRegions", "DescribeReservedInstances",
    "DescribeReservedInstancesOfferings", "DescribeRouteTables", "DescribeRules",
    "DescribeSecurityGroups", "DescribeServices", "DescribeSnapshots",
    "DescribeSpotFleetInstances", "DescribeSpotFleetRequests", "DescribeSpotInstanceRequests",
    "DescribeSpotPriceHistory", "DescribeStacks", "DescribeSubnets",
    "DescribeTable", "DescribeTargetGroups", "DescribeTaskDefinition",
    "DescribeTasks", "DescribeTrails", "DescribeVolumeAttribute",
    "DescribeVolumeStatus", "DescribeVolumes", "DescribeVpcAttribute",
    "DescribeVpcClassicLink", "DescribeVpcEndpoints", "DescribeVpcPeeringConnections",
    "DescribeVpcs", "DescribeVpnConnections", "DescribeVpnGateways",
    "DetachInternetGateway", "DetachNetworkInterface", "DetachRolePolicy",
    "DetachUserPolicy", "DetachVolume", "DisableKey",
    "DisableRule", "DisassociateAddress", "DisassociateIamInstanceProfile",
    "DisassociateRouteTable", "EnableAlarmActions", "EnableKey",
    "EnableMFADevice", "EnableRule", "EnableVpcClassicLink",
    "EncryptSecret", "FilterLogEvents", "GenerateDataKey",
    "GetAccessKeyLastUsed", "GetAccountAuthorizationDetails", "GetAccountPasswordPolicy",
    "GetAccountSummary", "GetBucketAcl", "GetBucketCORS",
    "GetBucketEncryption", "GetBucketLifecycle", "GetBucketLocation",
    "GetBucketLogging", "GetBucketNotification", "GetBucketObjectLockConfiguration",
    "GetBucketPolicy", "GetBucketPolicyStatus", "GetBucketPublicAccessBlock",
    "GetBucketReplication", "GetBucketTagging", "GetBucketVersioning",
    "GetBucketWebsite", "GetCallerIdentity", "GetConsoleLoginLink",
    "GetContextKeysForCustomPolicy", "GetDeployment", "GetDeploymentGroup",
    "GetElasticsearchDomainStatus", "GetFunction20150331", "GetFunctionConfiguration20150331",
    "GetGroup", "GetGroupPolicy", "GetHostedZone",
    "GetInstanceProfile", "GetKeyPolicy", "GetKeyRotationStatus",
    "GetObject", "GetObjectAcl", "GetObjectTagging",
    "GetPolicy", "GetPolicy202224v2", "GetPolicyVersion",
    "GetQueueAttributes", "GetQueueUrl", "GetRole",
    "GetRolePolicy", "GetSAMLProvider", "GetServerCertificate",
    "GetSessionToken", "GetStages", "GetUser",
    "GetUserPolicy", "ImportCertificate", "ImportKeyPair",
    "InitiateLayerUpload", "InviteAccountToOrganization", "LeaveOrganization",
    "ListAccessKeys", "ListAccountAliases", "ListAccounts",
    "ListAliases", "ListAttachedGroupPolicies", "ListAttachedRolePolicies",
    "ListAttachedUserPolicies", "ListBuckets", "ListCertificates",
    "ListChildren", "ListClusters", "ListContainerInstances",
    "ListDatabases", "ListDeploymentGroups", "ListDeployments",
    "ListElasticsearchDomains", "ListEntitiesForPolicy", "ListEventBuses",
    "ListFunctions202224", "ListGroupPolicies", "ListGroups",
    "ListGroupsForUser", "ListHostedZones", "ListImages",
    "ListInstanceProfiles", "ListInstanceProfilesForRole", "ListKeys",
    "ListMFADevices", "ListObjects", "ListObjectsV2",
    "ListOrganizationalUnitsForParent", "ListParents", "ListPolicies",
    "ListPolicyVersions", "ListQueues", "ListResourceTags",
    "ListRolePolicies", "ListRoles", "ListRoleTags",
    "ListSAMLProviders", "ListServerCertificates", "ListSigningCertificates",
    "ListSubscriptions", "ListSubscriptionsByTopic", "ListTables",
    "ListTagsForResource", "ListTargetsByRule", "ListTaskDefinitions",
    "ListTasks", "ListTopics", "ListUserPolicies",
    "ListUsers", "ListUserTags", "ListVirtualMFADevices",
    "LookupEvents", "ModifyDBInstance", "ModifyImageAttribute",
    "ModifyInstanceAttribute", "ModifyNetworkInterfaceAttribute", "ModifySnapshotAttribute",
    "ModifySubnetAttribute", "ModifyVpcAttribute", "MonitorInstances",
    "MoveAccount", "PutBucketAcl", "PutBucketCORS",
    "PutBucketEncryption", "PutBucketLifecycle", "PutBucketLogging",
    "PutBucketNotification", "PutBucketPolicy", "PutBucketPublicAccessBlock",
    "PutBucketReplication", "PutBucketTagging", "PutBucketVersioning",
    "PutBucketWebsite", "PutGroupPolicy", "PutItem",
    "PutObject", "PutObjectAcl", "PutRolePolicy",
    "PutScalingPolicy", "PutTargetsInRule", "PutUserPolicy",
    "RebootDBInstance", "RebootInstances", "RegisterScalableTarget",
    "RegisterTargets", "RemoveClientIDFromOpenIDConnectProvider", "RemoveLayerVersionPermission",
    "RemovePermission", "RemoveRoleFromInstanceProfile", "RemoveUserFromGroup",
    "RequestSpotFleet", "RequestSpotInstances", "ResyncMFADevice",
    "RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RotateSecret",
    "RunInstances", "RunTask", "SendMessage",
    "SetQueueAttributes", "StartInstances", "StartLogging",
    "StopInstances", "StopLogging", "Subscribe",
    "TagResource", "TagUser", "TerminateInstances",
    "UnmonitorInstances", "UnsubscribeFromTopic", "UpdateAccessKey",
    "UpdateAccountPasswordPolicy", "UpdateAlias", "UpdateAutoScalingGroup",
    "UpdateDBInstance", "UpdateDeploymentGroup", "UpdateFunction20150331",
    "UpdateFunctionCode20150331v2", "UpdateGroup", "UpdateRole",
    "UpdateRoleDescription", "UpdateSAMLProvider", "UpdateStack",
    "UpdateTable", "UpdateUser", "UploadLayerPart",
    "ViewBilling",
])

KNOWN_REGIONS: list[str] = sorted([
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2",
    "ca-central-1",
    "eu-central-1", "eu-north-1", "eu-west-1", "eu-west-2", "eu-west-3",
    "sa-east-1",
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
])

KNOWN_USER_TYPES: list[str] = sorted([
    "AWSAccount", "AWSService", "AssumedRole", "IAMUser", "Root", "Unknown",
])

# Columns used by OrdinalEncoder (must match FEATURE_NAMES order for categorical cols)
CATEGORICAL_FEATURES: list[str] = ["eventName", "userIdentitytype", "awsRegion"]

# ---------------------------------------------------------------------------
# 3. Known high-risk event names (used by threat classifier)
# ---------------------------------------------------------------------------

PRIVILEGE_ESCALATION_EVENTS: frozenset[str] = frozenset([
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreateAccessKey", "UpdateAccessKey",
    "AddUserToGroup", "CreatePolicy", "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
])

DEFENSE_EVASION_EVENTS: frozenset[str] = frozenset([
    "DeleteTrail", "StopLogging", "UpdateTrail",
    "DeleteFlowLogs", "DisableRule",
    "DeleteBucket",  # can remove log buckets
    "PutBucketLogging",  # can disable logging
    "DeleteConfigRule", "StopConfigurationRecorder",
])

RESOURCE_EXFILTRATION_EVENTS: frozenset[str] = frozenset([
    "GetObject", "ListBuckets", "ListObjects", "ListObjectsV2",
    "GetBucketAcl", "PutBucketAcl", "PutObjectAcl",
    "GetObjectAcl", "GetBucketPolicy", "PutBucketPolicy",
])

# ---------------------------------------------------------------------------
# 4. Feature extraction from a raw CloudTrail event
# ---------------------------------------------------------------------------

def extract_features(cloudtrail_event: dict[str, Any]) -> dict[str, Any]:
    """
    Parse a raw CloudTrail event dict and return a named feature dict.

    Handles two input shapes:
      (a) EventBridge CloudTrail envelope:
          {"detail": {"eventName": ..., "eventTime": ..., ...}}
      (b) Flat CloudTrail event dict:
          {"eventName": ..., "eventTime": ..., ...}

    Returns a dict with keys matching FEATURE_NAMES.
    All values are Python native types (str or int) — NOT yet encoded.
    """
    # Unwrap EventBridge envelope if present
    event = cloudtrail_event.get("detail", cloudtrail_event)

    # --- eventName ---
    event_name: str = str(event.get("eventName", "Unknown"))

    # --- hour (UTC) ---
    hour: int = _extract_hour(event.get("eventTime", ""))

    # --- userIdentitytype ---
    user_identity: dict = event.get("userIdentity", {})
    user_type: str = str(user_identity.get("type", event.get("userIdentitytype", "Unknown")))

    # --- awsRegion ---
    region: str = str(event.get("awsRegion", "us-east-1"))

    # --- isRoot (derived) ---
    is_root: int = 1 if user_type == "Root" else 0

    return {
        "eventName": event_name,
        "hour": hour,
        "userIdentitytype": user_type,
        "awsRegion": region,
        "isRoot": is_root,
    }


def build_dataframe(feature_dict: dict[str, Any]) -> pd.DataFrame:
    """
    Wrap a feature dict into a single-row DataFrame with FEATURE_NAMES columns.
    This is the only valid way to create a DataFrame for model input.
    """
    return pd.DataFrame([{
        col: feature_dict[col] for col in FEATURE_NAMES
    }])


def _extract_hour(event_time: str) -> int:
    """
    Extract the UTC hour (0–23) from a CloudTrail eventTime string.

    CloudTrail formats: "2017-02-01T12:34:56Z"  or  "2017-02" (truncated in dataset).
    Falls back to -1 (treated as unknown by encoder) if parsing fails.
    """
    if not event_time:
        return -1

    # Try full ISO-8601
    patterns = [
        r"(\d{4}-\d{2}-\d{2}T(\d{2}):\d{2}:\d{2})",  # 2017-02-01T12:34:56Z
        r"(\d{4}-\d{2}-\d{2} (\d{2}):\d{2}:\d{2})",  # 2017-02-01 12:34:56
    ]
    for pattern in patterns:
        m = re.search(pattern, str(event_time))
        if m:
            return int(m.group(2))

    return -1  # unknown hour; encoder will map to unknown_value=-1 category bucket
