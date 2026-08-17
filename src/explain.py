import pandas as pd
from sklearn.ensemble import IsolationForest
from google import genai 
from google.genai import types
import os 

client_ai = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])

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
    random_state = 42
)
model.fit(X)

df["anomaly_score"] = model.decision_function(X)
df["is_anomaly"] = model.predict(X)

flagged = df[df["is_anomaly"] == -1].sort_values("anomaly_score")
top_events = flagged.head(5)

for _, event in top_events.iterrows():

    prompt = f"""You are a security analyst assistant. Explain why the 
    following login event was flagged as anomalous. Be concise (3-4 sentences),
    plain-English, and suggest one concrete next step for a SOC analyst.

Event details:
- User: {event['username']}
- IP address: {event['ip']}
- Country: {event['country']}
- Login succeeded: {event['success']}
- Minutes since this user's previous login: {event['minutes_since_last_login']:.1f}
- Country changed from previous login: {bool(event['country_changed'])}
- Hours deviation from this user's typical login time: {event['hour_deviation']:.1f}
- Failed login attempts from this IP in the last 5 minutes; {event['ip_failed_5min']:.0f}
- Model anomaly score: {event['anomaly_score']:.4f} (lower = more anomalous)
"""

response = client_ai.models.generate_content(
    model="gemini-3.5-flash",
    contents=prompt,
    config = types.GenerateContentConfig(
        automatic_function_calling = types.AutomaticFunctionCallingConfig(disable=True)
    ),
)

print("=== Flagged Event ===")
print(f"{event['timestamp']} | {event['username']} | {event['ip']}")
print()
print("=== AI Explanation ===")
print(response.text)
print("\n" + "="*60 + "\n")
