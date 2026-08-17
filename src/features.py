import pandas as pd 

df = pd.read_csv("data/auth_logs.csv", parse_dates=["timestamp"])
df = df.sort_values(["username", "timestamp"]).reset_index(drop=True)

df["prev_timestamp"] = df.groupby("username")["timestamp"].shift(1)
df["minutes_since_last_login"] = (df["timestamp"] - df["prev_timestamp"]
).dt.total_seconds() / 60
median_gap = df["minutes_since_last_login"].median()
df["minutes_since_last_login"] = df["minutes_since_last_login"].fillna(median_gap)

df["prev_country"] = df.groupby("username")["country"].shift(1)
df["country_changed"] = (df["country"] != df["prev_country"]).astype(int)

df["hour"] = df["timestamp"].dt.hour
df["typical_hour"] = df.groupby("username")["hour"].transform("median")
df["hour_deviation"] = (df["hour"] - df["typical_hour"]).abs()

df["failed"] = (~df["success"]).astype(int)
df = df.sort_values(["ip", "timestamp"]).reset_index(drop=True)
rolled = (
    df.set_index("timestamp")
    .groupby("ip")["failed"]
    .rolling("5min")
    .sum()
)
df["ip_failed_5min"] = rolled.to_numpy()
df = df.sort_values("timestamp").reset_index(drop=True)

df["travel_risk"] = (
    (df["country_changed"] == 1) & (df["minutes_since_last_login"] < 60)
).astype(int)

feature_cols = [
    "timestamp", "username", "ip", "country", "success",
    "minutes_since_last_login", "country_changed",
    "hour_deviation", "ip_failed_5min", "travel_risk",
]
df_features = df[feature_cols]

df_features.to_csv("data/auth_logs_features.csv", index=False)

print(f"Feature-engineered {len(df_features)} rows -> data/auth_logs_features.csv")
print(df_features.sort_values("ip_failed_5min", ascending=False).head(5))
