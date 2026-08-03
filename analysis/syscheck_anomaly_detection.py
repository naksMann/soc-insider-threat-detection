"""
SOC Insider Threat Detection - Isolation Forest over Wazuh Syscheck events.

Reads a Wazuh Syscheck (File Integrity Monitoring) export, engineers five
behavioural features per file event, and scores each event with an
Isolation Forest so the events that deviate most from each agent's normal
file activity surface as anomalies.

Input : syscheck.json - a raw Wazuh API/indexer export of syscheck alerts
        (the "hits.hits" search-result shape).
Output: syscheck_anomaly_results.csv - every event scored, anomalies flagged.
"""

import json
import pandas as pd
from sklearn.ensemble import IsolationForest

SYSCHECK_EXPORT = "syscheck.json"
RESULTS_CSV = "syscheck_anomaly_results.csv"

# =========================
# 1. LOAD WAZUH SYSCHECK DATA
# =========================
with open(SYSCHECK_EXPORT, "r") as f:
    data = json.load(f)

events = data.get("hits", {}).get("hits", [])

print("==============================")
print(" WAZUH ML ANALYSIS STARTED")
print("==============================")
print(f"\nTotal events collected: {len(events)}")

# =========================
# 2. EXTRACT RECORDS
# =========================
records = []

for event in events:
    source = event.get("_source", {})
    syscheck = source.get("syscheck", {})
    agent = source.get("agent", {})

    if not syscheck:
        continue

    file_path = syscheck.get("path", "unknown")

    records.append({
        "agent_name": agent.get("name", "unknown"),
        "file_path": file_path,
        "event_type": syscheck.get("event", "unknown"),
        "file_size": syscheck.get("size_after", 0),
        # perm_after is the field Wazuh writes when a file's permissions
        # change; adjust the key here if your syscheck export uses a
        # different name (e.g. plain "perm").
        "perm": syscheck.get("perm_after", ""),
        "is_root": 1 if "/root" in file_path or "/etc" in file_path else 0,
    })

df = pd.DataFrame(records)

print("\nSample of collected data:")
print(df.head(5))

# =========================
# 3. FEATURE ENGINEERING
# =========================
# File path depth - how deeply nested the touched file is.
df["file_depth"] = df["file_path"].apply(lambda p: p.count("/"))

# Permission-string length - a crude proxy for unusual permission changes.
df["perm_length"] = df["perm"].apply(lambda x: len(x) if isinstance(x, str) else 0)

FEATURE_COLS = ["file_size", "file_depth", "is_root", "perm_length"]
features = df[FEATURE_COLS]

# =========================
# 4. TRAIN ISOLATION FOREST
# =========================
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,  # assume ~5% of events are anomalous
    random_state=42,
)

df["anomaly"] = model.fit_predict(features)
df["anomaly_score"] = model.decision_function(features)

# =========================
# 5. SHOW DETECTED ANOMALIES
# =========================
anomalies = df[df["anomaly"] == -1]

print("\n==============================")
print(" ANOMALY SUMMARY")
print("==============================")
print(f"Total events analyzed: {len(df)}")
print(f"Anomalies detected: {len(anomalies)}")

print("\nTop suspicious events:")
print(anomalies[[
    "agent_name",
    "file_path",
    "event_type",
    "file_size",
    "is_root",
    "anomaly_score",
]].to_string(index=False))

# =========================
# 6. SAVE RESULTS
# =========================
df.to_csv(RESULTS_CSV, index=False)
print(f"\nResults saved to {RESULTS_CSV}")
print("Analysis completed successfully.")
