#!/usr/bin/env python3
"""
Derive 50 test cases directly from the Kaggle Bot-IoT dataset.
Categories: DDoS, DoS, Reconnaissance, Theft, Normal
"""

import json
import pathlib
import random
import pandas as pd

BOT_IOT_CSV = pathlib.Path("data/Bot_IoT.csv")  
OUT_PATH = pathlib.Path("data/bot_iot_cases.jsonl")

TARGET_CATEGORIES = {
    "DDoS": 12,
    "DoS": 12,
    "Reconnaissance": 12,
    "Theft": 12,
    "Normal": 14,
}

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

REQUIRED_COLUMNS = [
    "saddr", "sport", "daddr", "dport", "proto",
    "sbytes", "dbytes", "attack", "category"
]

def main():

    if not BOT_IOT_CSV.exists():
        raise SystemExit(f"Bot-IoT CSV not found: {BOT_IOT_CSV}")

    print("[+] Loading dataset…")
    df = pd.read_csv(BOT_IOT_CSV)

    # Ensure columns exist
    for c in REQUIRED_COLUMNS:
        if c not in df.columns:
            raise SystemExit(f"Missing expected column: {c}")

    rows_out = []

    for cat, n_needed in TARGET_CATEGORIES.items():
        subset = df[df["category"] == cat]

        if subset.empty:
            print(f"[!] Warning: no rows for {cat}")
            continue

        chosen = subset.sample(
            n=min(n_needed, len(subset)),
            random_state=RANDOM_SEED
        )

        print(f"[+] Selected {len(chosen)} rows for category {cat}")

        for idx, row in chosen.iterrows():
            case_id = f"botiot_{cat.lower()}_{idx}"

            action_category = "A" if int(row["attack"]) == 1 else "nonA"

            log_obj = {
                "event_type": "network_connection",
                "src_ip": str(row["saddr"]),
                "src_port": int(row["sport"]) if row["sport"] != '-' else 0,
                "dst_ip": str(row["daddr"]),
                "dst_port": int(row["dport"]) if row["dport"] != '-' else 0,
                "protocol": str(row["proto"]).lower(),
                "bytes_sent": int(row["sbytes"]),
                "bytes_received": int(row["dbytes"]),
                "attack_label": cat
            }

            rows_out.append({
                "id": case_id,
                "category": action_category,
                "log": log_obj
            })

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w") as f:
        for obj in rows_out:
            f.write(json.dumps(obj) + "\n")

    print(f"[+] Wrote {len(rows_out)} cases → {OUT_PATH}")

if __name__ == "__main__":
    main()