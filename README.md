# CloudSecure

**Cloud + ML Engineering & MLOps Platform**

CloudSecure is an advanced, event-driven AWS cloud platform that ingests real-time infrastructure telemetry, processes it through an unsupervised Machine Learning pipeline (Isolation Forest), and provides deep, actionable explainability using SHAP (SHapley Additive exPlanations). 

While the primary application use-case is **security anomaly detection**, the core identity of CloudSecure is a scalable **Cloud Engineering and MLOps platform**. It demonstrates how to integrate serverless AWS infrastructure with robust machine learning models, CI/CD pipelines, and Infrastructure as Code (IaC).

---

## 📖 Problem Statement

Modern cloud environments generate millions of API events daily. Rule-based monitoring systems are noisy, rigid, and struggle to detect novel or "zero-day" anomalies. Furthermore, when "black-box" machine learning models flag an anomaly, operations teams are left without context, making it impossible to confidently automate remediation.

**CloudSecure solves this by:**
1. Ingesting AWS CloudTrail events in real-time.
2. Using unsupervised ML (Isolation Forest) to isolate anomalies without relying on predefined rules.
3. Leveraging SHAP (Explainable AI) to attribute exact feature contributions to the anomaly score.
4. Providing a highly polished, interactive Streamlit UI for operational review and automated IAM policy remediation.

---

## 🌟 Key Features & Methodologies

### 🧠 Machine Learning Intelligence
- **Isolation Forest:** An unsupervised anomaly detection algorithm from `scikit-learn`. Instead of profiling "normal" data, it explicitly isolates anomalies by measuring the path length of data points in random decision trees. Anomalies (rare events) have shorter path lengths.
- **Feature Engineering:** Raw CloudTrail JSON is transformed into a robust feature vector (e.g., temporal encoding of event times, IP frequency mapping, categorical encoding of AWS regions and API services).
- **Risk Scoring (0-100):** The raw anomaly score is mathematically normalized into an intuitive 0-100 Risk Score.
- **SHAP / Explainable AI (XAI):** Uses `shap.TreeExplainer` to break down every inference. The dashboard visualizes exactly *why* a score was generated (e.g., "Score increased by +42 because the API call occurred at 3 AM from an anomalous IP").
- **Offline Evaluation (80/20):** Evaluated against a synthetically poisoned AWS dataset using an 80/20 train-test split. The model achieves robust Precision, Recall, and F1 scores, correctly identifying sophisticated deviations (such as anomalous `AssumeRole` calls) while minimizing false positives on routine `DescribeInstances` events.

### 🏗️ Cloud Infrastructure
- **AWS CloudTrail & EventBridge:** Provides the real-time event bus and API telemetry.
- **AWS Lambda (Docker):** The core inference engine. Packaged as a Docker container stored in **Amazon ECR** to bypass standard Lambda size limits, allowing the deployment of heavy data science libraries (`pandas`, `scikit-learn`, `shap`).
- **Amazon DynamoDB:** A low-latency NoSQL datastore used to persist event payloads, ML scores, SHAP values, and remediation states.

### ⚙️ DevOps, IaC & CI/CD
- **Terraform:** Full Infrastructure as Code (IaC) deployment for all AWS resources, ensuring reproducible environments.
- **GitHub Actions & AWS OIDC:** Secure, keyless CI/CD pipeline. GitHub Actions assumes a least-privilege IAM role via OpenID Connect to build the Docker image, run the `pytest` suite, and push to ECR.

---

## 🔄 End-to-End Data Flow

1. **Ingestion:** An AWS API call occurs. CloudTrail logs it and EventBridge triggers the pipeline.
2. **Compute:** The event is routed to the Dockerized AWS Lambda function.
3. **Inference:** The Lambda extracts features, encodes them, and passes the vector to the Isolation Forest model.
4. **Explainability:** If an anomaly is detected, SHAP calculates the exact feature attributions.
5. **Storage:** The raw event, risk score, and SHAP JSON are saved to DynamoDB.
6. **Visualization:** The Streamlit frontend queries DynamoDB, rendering the data in the CloudSecure dashboard.
7. **Action:** Through the UI, an engineer reviews the SHAP explanation and clicks "Approve Remediation", which dynamically generates an AWS IAM Deny policy and attaches it to the offending Principal.

---

## 💻 Dashboard Pages

- **Overview:** High-level metrics, 0-100 Risk Score distributions, and pipeline status.
- **Event Investigation:** Deep dive into specific events with interactive SHAP bar charts and raw JSON payloads.
- **Analytics:** Macro-level trends, geographic IP mapping, and API service volume analysis.
- **ML Intelligence:** Visualizes model hyperparameters, evaluation metrics (F1/Precision/Recall), and the Isolation Forest boundary mechanics.
- **Cloud Infrastructure:** Real-time `boto3` diagnostics pinging DynamoDB, Lambda, ECR, and EventBridge to ensure backend health.
- **Architecture:** The complete architectural flow.

### LIVE vs DEMO Mode
CloudSecure operates in two modes:
- **LIVE Mode:** Actively queries DynamoDB for real AWS events.
- **DEMO Mode:** If the DynamoDB table is empty (or AWS access is restricted), the backend injects realistic, mathematically consistent synthetic events into the dashboard to demonstrate the UI, SHAP charts, and ML features.

---

## 🛠️ Project Structure

```text
CloudSecure/
├── backend/
│   ├── Dockerfile
│   ├── lambda_function.py
│   ├── ml_inference.py
│   ├── xai_explainer.py
│   ├── remediation.py
│   └── requirements.txt
├── frontend/
│   ├── app.py
│   ├── utils.py
│   ├── pages/
│   └── assets/
├── terraform/
│   ├── main.tf
│   ├── lambda.tf
│   └── dynamodb.tf
├── tests/
│   ├── test_feature_contract.py
│   └── test_full_validation.py
├── .github/workflows/
│   └── deploy.yml
└── README.md
```

---

## 🚀 Setup & Deployment Instructions

### Prerequisites
- Python 3.10+
- AWS CLI configured
- Terraform installed
- Docker (optional, for local image testing)

### Local Testing (Dashboard)

1. Clone the repository.
2. Navigate to the frontend directory:
   ```bash
   cd frontend
   pip install -r requirements.txt
   ```
3. Run the Streamlit dashboard:
   ```bash
   python -m streamlit run app.py
   ```
4. Open `http://localhost:8501`.

### Running the Test Suite

The repository contains a robust suite of 126 `pytest` unit tests covering the ML contract, feature encoding, and Lambda execution paths.
```bash
python -m pytest tests/ -v
```

### AWS Deployment (Terraform)

*Note: Ensure your AWS account is configured and you have the necessary permissions to create IAM roles, Lambda functions, ECR repositories, and DynamoDB tables.*

1. Navigate to the Terraform directory:
   ```bash
   cd terraform
   terraform init
   ```
2. Review the plan:
   ```bash
   terraform plan -out=tfplan
   ```
3. Apply the infrastructure:
   ```bash
   terraform apply tfplan
   ```
*(Note: The Lambda deployment depends on the ECR Docker image. You may need to trigger the GitHub Action or push the Docker image manually before the Lambda module can apply successfully).*

---

## 🚧 Limitations & Future Improvements

- **Cold Starts:** Because the Lambda function utilizes a Docker container loaded with heavyweight ML libraries (`scikit-learn`, `shap`), cold start times can occasionally exceed 5-7 seconds. Provisioned Concurrency can be configured via Terraform to mitigate this.
- **State Management:** Currently, remediations are tracked as a string state in DynamoDB. A future iteration could integrate AWS Step Functions for robust, multi-step remediation workflows.
- **Model Drift:** The current Isolation Forest is trained offline and serialized. Future iterations should implement a continuous retraining pipeline (e.g., using AWS SageMaker Pipelines) to adapt to shifting baseline cloud behaviors.

---

**Author:** Sanidhya Bhandari  
**Focus:** Cloud Engineering, Machine Learning Operations (MLOps), AI-Driven Infrastructure
