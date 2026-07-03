import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load dataset
df = pd.read_csv("../data/cloudtrail_logs.csv")

# Convert categorical columns to numbers
df["eventName"] = df["eventName"].astype("category").cat.codes
df["userType"] = df["userType"].astype("category").cat.codes
df["region"] = df["region"].astype("category").cat.codes

# Features
X = df[["eventName", "hour", "userType", "region", "isRoot"]]

# Train model
model = IsolationForest(
    contamination=0.2,
    random_state=42
)

model.fit(X)

# Save model
joblib.dump(model, "model.pkl")

print("Model trained successfully!")
print("model.pkl created")