#!/usr/bin/env python3
"""
Neuro-Sentry Phase 5 — Export Audit Logs as Training Data
Reads audit_log from neuro_sentry.db and exports as training data.

Usage:
    python backend/scripts/export_audit_as_training_data.py

Output:
    Appends to backend/data/train.csv (or creates audit_export.csv)
"""

import sqlite3
import sys
from pathlib import Path

import pandas as pd

SCRIPT_DIR  = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
DB_PATH     = BACKEND_DIR / "neuro_sentry.db"
DATA_DIR    = BACKEND_DIR / "data"
OUTPUT_CSV  = DATA_DIR / "audit_export.csv"


def main():
    print("\n" + "=" * 60)
    print("🛡️  NEURO-SENTRY — Audit Log Export (Phase 5)")
    print("=" * 60 + "\n")

    if not DB_PATH.exists():
        print(f"❌ Database not found at {DB_PATH}")
        print("   Run the backend first to generate audit logs.")
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Query audit logs — only rows with prompt_preview (truncated to 80 chars)
    cursor = conn.execute("""
        SELECT
            prompt_preview,
            decision,
            attack_type,
            risk_score,
            rule_score,
            llm_label,
            llm_confidence
        FROM audit_log
        WHERE prompt_preview IS NOT NULL
          AND prompt_preview != ''
          AND length(prompt_preview) >= 10
        ORDER BY timestamp DESC
    """)

    rows = []
    for row in cursor:
        text = row["prompt_preview"].strip()
        decision = row["decision"]
        attack_type = row["attack_type"] or "none"

        # Map pipeline decision to binary label
        if decision in ("block", "flag"):
            label = 1
        else:
            label = 0

        # Only include if the pipeline was reasonably confident
        # (avoid training on uncertain predictions)
        risk_score = row["risk_score"] or 0
        if label == 1 and risk_score < 40:
            continue  # too borderline — skip
        if label == 0 and risk_score > 30:
            continue  # possibly mislabeled — skip

        rows.append({
            "text": text,
            "label": label,
            "attack_type": attack_type if label == 1 else "none",
            "source": "audit_log",
        })

    conn.close()

    if not rows:
        print("⚠️  No suitable rows found in audit_log.")
        print("   Either the DB is empty or all entries are too borderline.")
        return

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(rows)
    # Remove duplicates
    df = df.drop_duplicates(subset="text")

    print(f"📊 Exported {len(df)} rows from audit_log:")
    print(f"   Benign (0):    {(df['label'] == 0).sum()}")
    print(f"   Malicious (1): {(df['label'] == 1).sum()}")

    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n💾 Saved to {OUTPUT_CSV}")

    # Optionally merge with train.csv
    train_csv = DATA_DIR / "train.csv"
    if train_csv.exists():
        existing = pd.read_csv(train_csv)
        merged = pd.concat([existing, df], ignore_index=True)
        merged = merged.drop_duplicates(subset="text")
        merged.to_csv(train_csv, index=False)
        print(f"📎 Merged into {train_csv} — total: {len(merged)} samples")
    else:
        print(f"ℹ️  Run collect_dataset.py first, then re-run this to merge.")

    print()


if __name__ == "__main__":
    main()
