# Security Log Anomaly Detector

An unsupervised anomaly detection pipeline for authentication logs, combining a classical ML model (Isolation Forest) with an LLM-based explanation layer that translates flagged events into plain-English, analyst-ready triage notes.

Built as a portfolio project to demonstrate applied security + AI skills, specifically, reducing SOC alert fatigue by pairing statistical anomaly detection with automated, human-readable explanations.

## How it works

1. **`src/generate_logs.py`** - generates 2 weeks of realistic synthetic authentication logs for 30 fake users, with 3 known attack patterns deliberately injected: brute force, impossible travel, and an off-hours login. This provides ground truth to validate the detector against.

2. **`src/features.py`** - engineers 5 features per login event, each measuring deviation from a specific user or IP's own normal behavior (not a global rule):
- `minutes_since_last_login`
- `country_changed`
- `hour_deviation` (from that user's own typical login hour, via median)
- `ip_failed_5min` (failed attempts from the same IP in a rolling window)
- `travel_risk` (combined signal: country change + short time gap)

3. **`src/detect.py`** - trains an unsupervised Isolation Forest on these features and scores every event for anomalousness.

4. **`src/explain.py`** - sends the top flagged events (with their raw feature values) to Gemini, which generates a concise, plain-English explanation and a concrete next step for a SOC analyst.

## Key design decisions

**Why Isolation Forest, unsupervised:** in a real SOC, you don't have a labeled dataset of "here are all our past breaches" to train a supervised classifier on. Isolation Forest learns the shape of normal behavior and flags statistical outliers, without ever being told what an attack looks like which is closer to how real-world anomaly detection has to work.

**Why features are per-entity, not global:** a login at 3AM is normal for a night-shift admin and highly unusual for someone who only ever logs in 9-5. Every feature here is computed relative to that specific user's (or IP's) own history, not a fixed rule like "flag anything after 10PM."

**Why `username` and `ip` are excluded from the model's training input:** including them would let the model "memorize" that a specific user or IP is bad, which wouldn't generalize which is important since a real attacker could use new IPs and target new accounts each time. The model only sees behavioral signals.

**Why the AI explanation layer exists at all:** the Isolation Forest outputs a numeric anomaly score and 5 raw feature values which are useful to a model, but not immediately useful to a human triaging an alert queue quickly. The LLM layer exists specifically to close that gap.

## Debugging notes

Two real issues came up during development, worth documenting because the diagnosis process is arguably more instructive than the final fix:

**1. Duplicate timestamp index breaking a rolling calculation:**
Computing `ip_failed_5min` initially used `.set_index("timestamp")` before a `.groupby("ip").rolling("5min")` call. This failed with `ValueError: cannot reindex on an axis with duplicate labels`, because multiple login events can share the exact same timestamp which is completely normal in real data, but incompatible with pandas' index-based row matching. Fixed by sorting explicitly by `["ip", "timestamp"]`, computing the rolling result separately, and assigning it back via `.to_numpy()` (positional assignment) instead of relying on pandas to match rows by a non-unique index.

**2. A sentinel value for missing data becoming a false-positive source.**
Each user's very first login has no prior login to compare against, so `minutes_since_last_login` was initially filled with a placeholder value of `999999` for those rows. This backfired: Isolation Forest correctly identified `999999` as a statistical outlier, but it was only extreme because it encoded missing data, not because it reflected a real anomaly. Every user's first login in the dataset was getting flagged for no genuine reason. Fixed by filling missing values with the dataset's **median** gap instead of an arbitrary large number, representing "no information" as unremarkable, rather than as an extreme value the model would key in on.

## Limitations

**False positives are a real tradeoff, not eliminated.** Loosening the model's `contamination` threshold from 0.01 to 0.03 was necessary to catch the subtler off-hours login pattern, but it also flags a handful of genuinely normal logins alongside the true anomalies. This mirrors a real SOC tradeoff: a stricter threshold misses subtle attacks, a looser one increases analyst workload from false alerts. Tuning this in production would require real labeled incident data and likely a cost-weighted approach rather than a fixed percentage.

**Synthetic data, not production traffic.** All logs are generated, not real. This was a deliberate choice for a portfolio project: it provides ground truth to validate against, which real unlabeled production data would not. The detection logic and feature engineering approach would carry over to real data, but thresholds and specific feature definitions would need returning against actual traffic patterns.

**No feedback loop.** A production version would need a way for analyst decisions (real attack vs. false positive) to feed back into the model over time, which this project does not implement.

**Impossible travel detection relies on a hand-engineered combined feature (`travel_risk`)** rather than the model discovering that interaction on its own from `country_changed` and `minutes_since_last_login` individually. This was a deliberate fix after diagnosing that the raw signal magnitudes were not extreme enough for Isolation Forest to isolate that pattern unaided.

## Setup

```bash
git clone 
cd security-anomaly-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

You'll need a free Gemini API key from [aistudio.google.com](https://aistudio.google.com) for the explanation layer. Set it as an environment variable:

```bash
export GOOGLE_API_KEY="your-key-here"
```

## Usage

Run the pipeline in order:

```bash
python src/generate_logs.py   # generates data/auth_logs.csv
python src/features.py        # generates data/auth_logs_features.csv
python src/detect.py          # trains model, prints flagged events
python src/explain.py         # generates AI explanations for top flagged events


## Example output 

```
=== Flagged Event ===
2026-08-06 03:00:00 | user007 | 185.220.101.5

=== AI Explanation ===
This failed login attempt was flagged because the user tried to log in from Russia—marking an abrupt country change from their previous login—and did so eight hours outside of their typical daily schedule. This extreme geographic and behavioral deviation, combined with the login failure, strongly suggests a potential credential stuffing or unauthorized access attempt. As a concrete next step, the SOC analyst should look up the IP address (185.220.101.5) on threat intelligence platforms to see if it is a known Tor exit node or malicious proxy, and proactively trigger a password reset for user007.
```