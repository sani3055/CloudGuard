# CloudGuard – Intelligent AWS Cloud Security Monitoring Platform

## Overview

CloudGuard is an event-driven AWS cloud security monitoring platform that detects security-sensitive AWS API activities, assigns risk scores, generates real-time alerts, stores threat events, and provides an interactive dashboard for monitoring cloud security.

The project is built using AWS serverless services and demonstrates cloud architecture, security monitoring, event-driven processing, and dashboard visualization.

---

## Features

- Real-time AWS event monitoring
- Event-driven architecture using EventBridge
- Risk-based threat detection
- CloudTrail event processing
- Real-time SNS email alerts
- DynamoDB threat storage
- Interactive Streamlit dashboard
- Threat history with search and filtering
- Security analytics dashboard
- Modular architecture for future ML integration

---

## AWS Services Used

- AWS CloudTrail
- Amazon EventBridge
- AWS Lambda
- Amazon DynamoDB
- Amazon SNS
- Amazon CloudWatch
- AWS IAM

---

## Architecture

```
                    CloudTrail
                         │
                         ▼
                  Amazon EventBridge
                         │
                         ▼
                  AWS Lambda
                  (Risk Engine)
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
     DynamoDB        Amazon SNS    CloudWatch
          │
          ▼
  Streamlit Dashboard
```

---

## Dashboard Modules

### Dashboard

- Threat overview
- KPI cards
- Threat timeline
- Severity distribution
- Event distribution

### Threat History

- Search threats
- Severity filtering
- CSV export

### Analytics

- Threats by region
- Threats by user type
- Risk score analysis

### Threat Details

- Event information
- Risk score
- Severity
- Region
- User type
- Event source

### ML Insights

Reserved for the upcoming anomaly detection module.

---

## Project Structure

```
CloudGuard
│
├── backend/
│   └── lambda_function.py
│
├── frontend/
│   ├── app.py
│   ├── utils.py
│   ├── requirements.txt
│   ├── pages/
│   └── .streamlit/
│
├── ml/
│
├── docs/
│
├── .gitignore
└── README.md
```

---

## Technology Stack

### Cloud

- AWS Lambda
- EventBridge
- CloudTrail
- DynamoDB
- SNS
- CloudWatch
- IAM

### Backend

- Python
- Boto3

### Frontend

- Streamlit
- Plotly
- Pandas

### Database

- Amazon DynamoDB

---

## Current Workflow

1. AWS CloudTrail captures API activity.
2. EventBridge filters security-sensitive events.
3. Lambda calculates a risk score.
4. Threat events are stored in DynamoDB.
5. High-risk events trigger SNS email alerts.
6. Streamlit dashboard visualizes security events.

---

## Future Enhancements

- Machine Learning–based anomaly detection
- Isolation Forest integration
- Behavioral threat scoring
- Explainable AI recommendations
- Live CloudTrail event ingestion
- AWS deployment
- Authentication and role-based access
- Infrastructure as Code using Terraform or AWS CloudFormation

---

## Screenshots

Screenshots will be added after deployment.

---

## Author

**Sanidhya Bhandari**

Final Year B.Tech Computer Science Engineering

VIT Vellore