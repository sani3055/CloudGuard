# CloudGuard Lambda Container Image
# Deploys the full ML + XAI + IAM pipeline as a Lambda container.
#
# Build:
#   docker build -t cloudguard-lambda .
#
# Test locally (requires AWS credentials):
#   docker run -p 9000:8080 \
#     -e AWS_ACCESS_KEY_ID=... \
#     -e AWS_SECRET_ACCESS_KEY=... \
#     -e AWS_DEFAULT_REGION=eu-north-1 \
#     -e SIMULATION_MODE=true \
#     cloudguard-lambda
#
# Then invoke:
#   Invoke-RestMethod -Method POST `
#     -Uri "http://localhost:9000/2015-03-31/functions/function/invocations" `
#     -Body (Get-Content tests/sample_eventbridge_event.json -Raw) `
#     -ContentType "application/json"

FROM public.ecr.aws/lambda/python:3.11

# Set working directory to Lambda task root
WORKDIR ${LAMBDA_TASK_ROOT}

# Copy requirements and install dependencies first (layer-cache friendly)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy ML artefacts (encoder.pkl + model.pkl must exist before building)
COPY ml/encoder.pkl ./ml/encoder.pkl
COPY ml/model.pkl   ./ml/model.pkl

# Copy the feature contract (shared between training and inference)
COPY ml/feature_contract.py ./ml/feature_contract.py

# Copy backend source
COPY backend/config.py          ./config.py
COPY backend/lambda_function.py ./lambda_function.py
COPY backend/ml_inference.py    ./ml_inference.py
COPY backend/xai_explainer.py   ./xai_explainer.py
COPY backend/threat_classifier.py ./threat_classifier.py
COPY backend/iam_generator.py   ./iam_generator.py
COPY backend/policy_validator.py ./policy_validator.py
COPY backend/remediation.py     ./remediation.py

# Lambda handler
CMD ["lambda_function.handler"]
