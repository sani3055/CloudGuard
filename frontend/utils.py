import boto3
import pandas as pd
import streamlit as st


# ----------------------------
# DynamoDB Connection
# ----------------------------

@st.cache_resource
def get_table():
    dynamodb = boto3.resource(
        "dynamodb",
        region_name="eu-north-1"
    )

    return dynamodb.Table("ThreatEvents")


# ----------------------------
# Load Threat Data
# ----------------------------

@st.cache_data(ttl=30)
def load_data():

    table = get_table()

    response = table.scan()

    items = response.get("Items", [])

    if not items:
        return pd.DataFrame()

    df = pd.DataFrame(items)

    # Ensure required columns exist
    defaults = {
        "severity": "Unknown",
        "region": "Unknown",
        "userType": "Unknown",
        "eventSource": "Unknown",
        "sourceIP": "Unknown",
        "riskScore": 0
    }

    for col, default in defaults.items():

        if col not in df.columns:
            df[col] = default

        df[col] = df[col].fillna(default)

    df["riskScore"] = df["riskScore"].astype(int)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df


# ----------------------------
# Severity Colors
# ----------------------------

def color_severity(val):

    colors = {
        "Critical": "background-color:#d32f2f;color:white;",
        "High": "background-color:#f57c00;color:white;",
        "Medium": "background-color:#fbc02d;color:black;",
        "Low": "background-color:#388e3c;color:white;",
        "Unknown": ""
    }

    return colors.get(val, "")