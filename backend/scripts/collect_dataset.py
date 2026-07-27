#!/usr/bin/env python3
"""
Neuro-Sentry — Dataset Collection (Phase 7)
Downloads and merges public + local datasets into a clean JSONL.
NO augmentation here — augmentation happens in train_classifier.py
after the train/val/test split to prevent leakage.

Target: collect as many clean samples as available, balanced by label.

Sources:
  Attack: deepset, jackhhao, rubend18, local
  Benign: deepset benign rows, alpaca, oasst1, local, WildChat

Usage:
    cd backend && ./venv/bin/python scripts/collect_dataset.py

Output:
    backend/data/dataset.jsonl  — fields: text, label (0=benign, 1=attack)
"""

import json
import random
import re
import sys
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────

SCRIPT_DIR  = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
DATA_DIR    = BACKEND_DIR / "data"
TEST_DIR    = BACKEND_DIR / "tests" / "datasets"
OUTPUT_FILE = DATA_DIR / "dataset.jsonl"

SEED = 42
random.seed(SEED)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def clean_text(text: str) -> str:
    """Strip and normalize whitespace."""
    if not text:
        return ""
    return re.sub(r'\s+', ' ', text.strip())[:3000]


def dedup_rows(rows: list, source_name: str = "") -> list:
    """Remove exact-text duplicates within a source (case-insensitive)."""
    seen = set()
    unique = []
    for r in rows:
        key = r["text"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(r)
    removed = len(rows) - len(unique)
    if removed:
        pfx = f"[{source_name}] " if source_name else ""
        print(f"   🧹 {pfx}Removed {removed} intra-source duplicates")
    return unique


def safe_load(name: str, loader):
    """Run a loader function, catch exceptions, return empty list on failure."""
    try:
        return loader()
    except Exception as e:
        print(f"   ⚠️  {name} unavailable: {e}")
        return []


# ─── Attack sources ──────────────────────────────────────────────────────────

def collect_deepset():
    """deepset/prompt-injections — binary injection detection."""
    print("📥 Downloading deepset/prompt-injections...")
    from datasets import load_dataset
    ds = load_dataset("deepset/prompt-injections", split="train")
    rows = []
    for item in ds:
        text = clean_text(item.get("text", item.get("prompt", "")))
        if len(text) < 5:
            continue
        label = int(item.get("label", 0))
        rows.append({"text": text, "label": label})
    rows = dedup_rows(rows, "deepset")
    n_atk = sum(r["label"] for r in rows)
    print(f"   ✅ {len(rows)} samples ({n_atk} attack, {len(rows)-n_atk} benign)")
    return rows


def collect_jackhhao():
    """jackhhao/jailbreak-classification — jailbreak labeled rows."""
    print("📥 Downloading jackhhao/jailbreak-classification...")
    from datasets import load_dataset
    try:
        ds = load_dataset("jackhhao/jailbreak-classification", split="train")
    except Exception:
        try:
            ds = load_dataset("jackhhao/jailbreak-classification", split="test")
        except Exception as e:
            print(f"   ⚠️  jackhhao unavailable: {e}")
            return []
    rows = []
    label_counts = {}
    for item in ds:
        text = clean_text(item.get("prompt", item.get("text", "")))
        if len(text) < 10:
            continue
        raw_label = item.get("label", item.get("type", 0))
        # Track raw label distribution for debugging
        label_counts[str(raw_label)] = label_counts.get(str(raw_label), 0) + 1
        if isinstance(raw_label, str):
            label = 1 if raw_label.lower() in ("jailbreak", "malicious", "1", "attack") else 0
        else:
            label = int(raw_label)
        rows.append({"text": text, "label": label})
    rows = dedup_rows(rows, "jackhhao")
    # Print raw label distribution for verification
    print(f"   📊 Raw label distribution: {label_counts}")
    n_atk = sum(r["label"] for r in rows)
    print(f"   ✅ {len(rows)} samples ({n_atk} attack, {len(rows)-n_atk} benign)")
    return rows


def collect_rubend18():
    """rubend18/ChatGPT-Jailbreak-Prompts — all are jailbreak."""
    print("📥 Downloading rubend18/ChatGPT-Jailbreak-Prompts...")
    from datasets import load_dataset
    ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
    rows = []
    for item in ds:
        text = clean_text(item.get("text", item.get("prompt", item.get("Prompt", ""))))
        if len(text) < 10:
            continue
        rows.append({"text": text, "label": 1})
    rows = dedup_rows(rows, "rubend18")
    print(f"   ✅ {len(rows)} attack samples")
    return rows


def collect_fashn():
    """fashn/injections — all are injection attacks."""
    print("📥 Downloading fashn/injections...")
    from datasets import load_dataset
    ds = load_dataset("fashn/injections", split="train")
    rows = []
    for item in ds:
        text = clean_text(item.get("text", item.get("prompt", item.get("content", ""))))
        if len(text) < 10:
            continue
        rows.append({"text": text, "label": 1})
    rows = dedup_rows(rows, "fashn")
    print(f"   ✅ {len(rows)} attack samples")
    return rows


def collect_prompt_security():
    """prompt-security/prompt-injection-dataset — all are injection attacks."""
    print("📥 Downloading prompt-security/prompt-injection-dataset...")
    from datasets import load_dataset
    ds = load_dataset("prompt-security/prompt-injection-dataset", split="train")
    rows = []
    for item in ds:
        text = clean_text(item.get("text", item.get("prompt", item.get("content", ""))))
        if len(text) < 10:
            continue
        rows.append({"text": text, "label": 1})
    rows = dedup_rows(rows, "prompt-security")
    print(f"   ✅ {len(rows)} attack samples")
    return rows


def collect_xtram1():
    """xTRam1/safe-guard-prompt-injection — attack-labeled rows only."""
    print("📥 Downloading xTRam1/safe-guard-prompt-injection...")
    from datasets import load_dataset
    ds = load_dataset("xTRam1/safe-guard-prompt-injection", split="train")
    rows = []
    label_counts = {}
    for item in ds:
        text = clean_text(item.get("text", item.get("prompt", item.get("content", ""))))
        if len(text) < 10:
            continue
        raw_label = item.get("label", item.get("safety", item.get("type", "")))
        label_counts[str(raw_label)] = label_counts.get(str(raw_label), 0) + 1
        # Keep only attack rows
        if isinstance(raw_label, str):
            is_attack = raw_label.lower() in ("attack", "injection", "jailbreak", "malicious", "unsafe", "1")
        else:
            is_attack = int(raw_label) == 1
        if is_attack:
            rows.append({"text": text, "label": 1})
    rows = dedup_rows(rows, "xTRam1")
    print(f"   📊 Raw label distribution: {label_counts}")
    print(f"   ✅ {len(rows)} attack samples (filtered from {sum(label_counts.values())} total)")
    return rows


def collect_harelix():
    """Harelix/prompt-injection-mixed-attacks-2024 — all are attacks."""
    print("📥 Downloading Harelix/prompt-injection-mixed-attacks-2024...")
    from datasets import load_dataset
    ds = load_dataset("Harelix/prompt-injection-mixed-attacks-2024", split="train")
    rows = []
    for item in ds:
        text = clean_text(item.get("text", item.get("prompt", item.get("content", ""))))
        if len(text) < 10:
            continue
        rows.append({"text": text, "label": 1})
    rows = dedup_rows(rows, "Harelix")
    print(f"   ✅ {len(rows)} attack samples")
    return rows


def collect_markush1():
    """markush1/LLM-Jailbreak-Classifier — jailbreak-labeled rows only."""
    print("📥 Downloading markush1/LLM-Jailbreak-Classifier...")
    from datasets import load_dataset
    ds = load_dataset("markush1/LLM-Jailbreak-Classifier", split="train")
    rows = []
    label_counts = {}
    for item in ds:
        text = clean_text(item.get("text", item.get("prompt", item.get("content", ""))))
        if len(text) < 10:
            continue
        raw_label = item.get("label", item.get("type", item.get("category", "")))
        label_counts[str(raw_label)] = label_counts.get(str(raw_label), 0) + 1
        if isinstance(raw_label, str):
            is_jailbreak = raw_label.lower() in ("jailbreak", "malicious", "attack", "1")
        else:
            is_jailbreak = int(raw_label) == 1
        if is_jailbreak:
            rows.append({"text": text, "label": 1})
    rows = dedup_rows(rows, "markush1")
    print(f"   📊 Raw label distribution: {label_counts}")
    print(f"   ✅ {len(rows)} jailbreak samples (filtered from {sum(label_counts.values())} total)")
    return rows


def collect_local_attacks():
    """Local hand-curated attacks from tests/datasets/attacks.json."""
    print("📥 Loading local attacks...")
    path = TEST_DIR / "attacks.json"
    if not path.exists():
        print("   ⚠️  attacks.json not found")
        return []
    data = json.loads(path.read_text())
    rows = []
    for item in data:
        text = clean_text(item if isinstance(item, str) else item.get("text", item.get("prompt", "")))
        if len(text) >= 5:
            rows.append({"text": text, "label": 1})
    rows = dedup_rows(rows, "local/attacks")
    print(f"   ✅ {len(rows)} local attack samples")
    return rows


# ─── Benign sources ──────────────────────────────────────────────────────────

def collect_alpaca():
    """tatsu-lab/alpaca — sample 2,500 instruction rows."""
    print("📥 Downloading tatsu-lab/alpaca...")
    from datasets import load_dataset
    ds = load_dataset("tatsu-lab/alpaca", split="train")
    all_texts = []
    for item in ds:
        text = clean_text(item.get("instruction", ""))
        inp = clean_text(item.get("input", ""))
        if inp:
            text = f"{text} {inp}"
        if len(text) >= 10:
            all_texts.append(text)
    random.shuffle(all_texts)
    rows = [{"text": t, "label": 0} for t in all_texts[:2500]]
    rows = dedup_rows(rows, "alpaca")
    print(f"   ✅ {len(rows)} benign samples (from {len(all_texts)} total)")
    return rows


def collect_oasst1():
    """OpenAssistant/oasst1 — sample 2,000 human (prompter) messages."""
    print("📥 Downloading OpenAssistant/oasst1...")
    from datasets import load_dataset
    ds = load_dataset("OpenAssistant/oasst1", split="train")
    all_texts = []
    for item in ds:
        if item.get("role") != "prompter":
            continue
        text = clean_text(item.get("text", ""))
        if len(text) >= 10:
            all_texts.append(text)
    random.shuffle(all_texts)
    rows = [{"text": t, "label": 0} for t in all_texts[:2000]]
    rows = dedup_rows(rows, "oasst1")
    print(f"   ✅ {len(rows)} benign samples (from {len(all_texts)} prompter msgs)")
    return rows


def collect_local_benign():
    """Local hand-curated benign from tests/datasets/benign.json."""
    print("📥 Loading local benign...")
    path = TEST_DIR / "benign.json"
    if not path.exists():
        print("   ⚠️  benign.json not found")
        return []
    data = json.loads(path.read_text())
    rows = []
    for item in data:
        text = clean_text(item if isinstance(item, str) else item.get("text", item.get("prompt", "")))
        if len(text) >= 5:
            rows.append({"text": text, "label": 0})
    rows = dedup_rows(rows, "local/benign")
    print(f"   ✅ {len(rows)} local benign samples")
    return rows


def collect_wildchat():
    """allenai/WildChat — English user turns to fill benign pool."""
    print("📥 Downloading allenai/WildChat (English user turns)...")
    from datasets import load_dataset
    try:
        ds = load_dataset("allenai/WildChat", split="train", streaming=True)
        all_texts = []
        seen = 0
        for item in ds:
            seen += 1
            if seen > 200000:  # scan up to 200k rows for more coverage
                break
            lang = item.get("language", "")
            if lang and lang.lower() != "english":
                continue
            conv = item.get("conversation", [])
            for turn in conv:
                if turn.get("role") == "user":
                    text = clean_text(turn.get("content", ""))
                    if len(text) >= 10:
                        all_texts.append(text)
                    break  # first user turn only
        random.shuffle(all_texts)
        rows = [{"text": t, "label": 0} for t in all_texts[:2500]]
        rows = dedup_rows(rows, "WildChat")
        print(f"   ✅ {len(rows)} benign samples (scanned {seen} rows, found {len(all_texts)} English)")
        return rows
    except Exception as e:
        print(f"   ⚠️  WildChat unavailable: {e}")
        return []


# ─── Cross-source dedup ──────────────────────────────────────────────────────

def cross_dedup(all_rows: list) -> list:
    """Remove cross-source duplicates (case-insensitive exact match)."""
    seen = set()
    unique = []
    for r in all_rows:
        key = r["text"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(r)
    removed = len(all_rows) - len(unique)
    if removed:
        print(f"🧹 Cross-source dedup removed {removed} duplicates")
    return unique


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 70)
    print("🛡️  NEURO-SENTRY — Dataset Collection (Phase 7)")
    print("=" * 70)
    print("   Collects clean data only — augmentation happens in train_classifier.py\n")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Collect attack samples ────────────────────────────────────────────
    print("━" * 40)
    print("⚔️  ATTACK SOURCES")
    print("━" * 40)

    attack_rows = []
    benign_from_attack_ds = []

    for name, loader in [
        ("deepset",          collect_deepset),
        ("jackhhao",         collect_jackhhao),
        ("rubend18",         collect_rubend18),
        ("fashn",            collect_fashn),
        ("prompt-security",  collect_prompt_security),
        ("xTRam1",           collect_xtram1),
        ("Harelix",          collect_harelix),
        ("markush1",         collect_markush1),
        ("local",            collect_local_attacks),
    ]:
        rows = safe_load(name, loader)
        attack_rows.extend(r for r in rows if r["label"] == 1)
        benign_from_attack_ds.extend(r for r in rows if r["label"] == 0)

    print(f"\n   ⚔️  Attack total: {len(attack_rows)}")
    print(f"   🟢 Benign from attack datasets: {len(benign_from_attack_ds)}")

    # ── Collect benign samples ────────────────────────────────────────────
    print(f"\n{'━' * 40}")
    print("🟢 BENIGN SOURCES")
    print("━" * 40)

    benign_rows = list(benign_from_attack_ds)
    for name, loader in [
        ("alpaca",   collect_alpaca),
        ("oasst1",   collect_oasst1),
        ("local",    collect_local_benign),
        ("WildChat", collect_wildchat),
    ]:
        benign_rows.extend(safe_load(name, loader))

    print(f"\n   🟢 Benign total: {len(benign_rows)}")

    # ── Merge + cross-source dedup ────────────────────────────────────────
    print(f"\n{'━' * 40}")
    print("📦 ASSEMBLY")
    print("━" * 40)

    all_rows = attack_rows + benign_rows
    all_rows = cross_dedup(all_rows)

    random.seed(SEED)
    random.shuffle(all_rows)

    # ── Stats ─────────────────────────────────────────────────────────────
    total = len(all_rows)
    n_attack = sum(1 for r in all_rows if r["label"] == 1)
    n_benign = sum(1 for r in all_rows if r["label"] == 0)

    print(f"\n{'─' * 70}")
    print(f"📊 Final Dataset:")
    print(f"   Total:    {total}")
    print(f"   Attack:   {n_attack} ({n_attack/total:.1%})")
    print(f"   Benign:   {n_benign} ({n_benign/total:.1%})")
    print(f"{'─' * 70}")

    if n_attack < 500:
        print(f"\n   ⚠️  Only {n_attack} attack samples — augmentation in train_classifier.py will compensate")
    if abs(n_attack - n_benign) / max(n_attack, n_benign) > 0.5:
        print(f"   ⚠️  Imbalanced dataset — class weights + augmentation in training will handle this")

    # ── Save as JSONL ─────────────────────────────────────────────────────
    with open(OUTPUT_FILE, "w") as f:
        for row in all_rows:
            f.write(json.dumps({"text": row["text"], "label": row["label"]}) + "\n")

    size_kb = OUTPUT_FILE.stat().st_size / 1024
    print(f"\n💾 Saved to {OUTPUT_FILE}")
    print(f"   File size: {size_kb:.1f} KB")
    print(f"   Format: JSONL (one JSON per line)")
    print(f"   ℹ️  Augmentation will be applied in train_classifier.py (train split only)")
    print()


if __name__ == "__main__":
    main()
