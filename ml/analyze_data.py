import pandas as pd

df = pd.read_csv("../data/dec12_18features.csv")

print("Shape:", df.shape)

print("\nEvent Names:")
print(df["eventName"].value_counts().head(20))

print("\nUser Types:")
print(df["userIdentitytype"].value_counts())

print("\nRegions:")
print(df["awsRegion"].value_counts())

print("\nEvent Sources:")
print(df["eventSource"].value_counts().head(20))