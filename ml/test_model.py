import joblib
import pandas as pd

# Load model
model = joblib.load("model.pkl")

# Suspicious Event
test_event = pd.DataFrame({
    "eventName": [0],
    "hour": [2],
    "userType": [1],
    "region": [0],
    "isRoot": [1]
})

prediction = model.predict(test_event)

print("Prediction:", prediction)

if prediction[0] == -1:
    print("Anomaly Detected")
else:
    print("Normal Activity")