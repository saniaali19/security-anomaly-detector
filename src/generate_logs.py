import csv
import random
from datetime import datetime, timedelta
random.seed(42)

USERS = [f"user{i:03d}" for i in range(1, 31)]
COUNTRIES = ["US", "US", "US", "US", "CA", "GB", "IN", "DE"]
IPS_BY_COUNTRY = {
    "US": ["73.12.44.{}", "98.201.6.{}", "24.15.88.{}"],
    "CA": ["70.66.12.{}"],
    "GB": ["81.2.69.{}"],
    "IN": ["117.198.4.{}"],
    "DE": ["85.214.132.{}"],
}

START = datetime(2026, 8, 1, 0, 0, 0)
DAYS = 14

def random_ip(country):
    template = random.choice(IPS_BY_COUNTRY[country])
    return template.format(random.randint(2, 254))

def normal_login_hour(user_seed):
    random.seed(user_seed)
    return random.randint(7, 18)

rows = []
for day in range(DAYS):
    date = START + timedelta(days=day)
    for user in USERS:
        typical_hour = normal_login_hour(hash(user) % 1000)
        num_logins = random.randint(1, 3)
        for _ in range(num_logins):
            hour = max(0, min(23, typical_hour + random.randint(-2, 2)))
            minute = random.randint(0, 59)
            ts = date.replace(hour=hour, minute=minute)
            country = random.choices(COUNTRIES, k=1)[0]
            ip = random_ip(country)
            success = random.random() > 0.03
            rows.append({
                "timestamp": ts.isoformat(),
                "username": user,
                "ip": ip,
                "country": country,
                "success": success,
            })

target_user = "user007"
attacker_ip = "185.220.101.5"
brute_start = START + timedelta(days=5, hours=3, minutes=0)
for i in range(25):
    ts = brute_start + timedelta(seconds=i*8)
    rows.append({
        "timestamp": ts.isoformat(),
        "username": target_user,
        "ip": attacker_ip,
        "country": "RU",
        "success": False
    })
rows.append({
    "timestamp": (brute_start + timedelta(seconds=25*8)).isoformat(),
    "username": target_user,
    "ip": attacker_ip,
    "country": "RU",
    "success": True,
})

travel_user = "user015"
t1 = START + timedelta(days=8, hours=9, minutes=0)
t2 = t1 + timedelta(minutes=20)
rows.append({
    "timestamp": t1.isoformat(),
    "username": travel_user,
    "ip": random_ip("US"),
    "country": "US",
    "success": True,
})
rows.append({
    "timestamp": t2.isoformat(),
    "username": travel_user,
    "ip": random_ip("DE"),
    "country": "DE",
    "success": True,
})

offhours_user = "user022"
ts = START + timedelta(days=11, hours=3, minutes=47)
rows.append({
    "timestamp": ts.isoformat(),
    "username": offhours_user,
    "ip": random_ip("US"),
    "country": "US",
    "success": True,
})

rows.sort(key=lambda r: r["timestamp"])
with open("data/auth_logs.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp", "username", "ip", "country", "success"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} log events -> data/auth_logs.csv")
print("Injected anomalies:")
print(f" - Brute force: {target_user} targeted from {attacker_ip} starting {brute_start.isoformat()}")
print(f" - Impossible travel: {travel_user} US->DE within 20 minutes at {t1.isoformat()}")
print(f" - Off-hours login: {offhours_user} at {ts.isoformat()}")