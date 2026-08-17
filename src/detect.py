import pandas as pd 
from sklearn.ensemble import IsolationForest

df = pd.read_csv("data/auth_logs_features.csv", parse_dates=["timestamp"])

feature_columns = [
    "minutes_since_last_login",
    "country_changed",
    "hour_deviation",
    "ip_failed_5min",
    "travel_risk",
]

X = df[feature_columns]

model = IsolationForest(
    n_estimators = 100,
    contamination = 0.03,
    random_state = 42,
)

model.fit(X)

df["anomaly_score"] = model.decision_function(X)
df["is_anomaly"] = model.predict(X)

known_anomalies = df[
    (df["username"] == "user015") & (df["timestamp"] == "2026-08-09 09:20:00")
    | (df["username"] == "user022") & (df["timestamp"] == "2026-08-12 03:47:00")
]
print(known_anomalies[["timestamp", "username", "anomaly_score", "is_anomaly"]])

flagged = df[df["is_anomaly"] == -1].sort_values("anomaly_score")
print(f"Flagged {len(flagged)} anomalous events out of {len(df)} total")
print(flagged[["timestamp", "username", "ip", "country", "anomaly_score"]])