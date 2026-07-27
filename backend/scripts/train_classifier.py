#!/usr/bin/env python3
"""
Neuro-Sentry — DistilBERT Fine-Tuning (Phase 7)
Trains distilbert-base-uncased for binary threat classification.

Input:  backend/data/dataset.jsonl  (from collect_dataset.py)
Output: backend/models/classifier/  — saved model + tokenizer + metrics.json

Augmentation is applied ONLY to the training split AFTER the
train/val/test split to prevent data leakage.

Usage:
    cd backend && ./venv/bin/python scripts/train_classifier.py

Split: 70% train / 15% val / 15% test (test is held-out, never seen in training)
"""

import argparse
import json
import os
import random
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
)

# ─── Config ───────────────────────────────────────────────────────────────────

BASE_MODEL = "distilbert-base-uncased"
LABEL_MAP  = {0: "benign", 1: "malicious"}

# ─── Paths ────────────────────────────────────────────────────────────────────

SCRIPT_DIR  = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
DATA_DIR    = BACKEND_DIR / "data"
MODEL_DIR   = BACKEND_DIR / "models" / "classifier"

DATASET_FILE = DATA_DIR / "dataset.jsonl"


# ─── Augmentation (applied ONLY to train split) ──────────────────────────────

FILLER_PREFIXES = [
    "Hey, I have a question for you. ",
    "I was wondering about something. ",
    "Quick question: ",
    "Could you help me with this? ",
    "I need your assistance. ",
    "Please answer the following. ",
    "Looking for some guidance here. ",
    "This is important: ",
    "I'd like to know: ",
    "For my research project, I need to: ",
]

SYNONYMS = {
    "ignore": ["disregard", "bypass", "skip", "override"],
    "instructions": ["guidelines", "rules", "directives", "commands"],
    "previous": ["prior", "earlier", "above", "preceding"],
    "system": ["core", "base", "root", "internal"],
    "reveal": ["show", "display", "output", "print"],
    "prompt": ["instruction", "directive", "input", "query"],
    "admin": ["administrator", "root user", "superuser", "operator"],
    "pretend": ["act as if", "imagine", "suppose", "assume"],
}


def augment_text(text: str, rng: random.Random) -> str:
    """Deterministic augmentation: synonym swap + optional filler prefix."""
    result = text
    for word, alts in SYNONYMS.items():
        if word in result.lower():
            replacement = rng.choice(alts)
            result = re.sub(rf'\b{word}\b', replacement, result, count=1, flags=re.IGNORECASE)
    if rng.random() < 0.4:
        result = rng.choice(FILLER_PREFIXES) + result
    if rng.random() < 0.3:
        sentences = result.split('. ')
        if len(sentences) > 2:
            rng.shuffle(sentences)
            result = '. '.join(sentences)
    return result


def augment_train_split(train_df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """
    Balance the training split via augmentation.
    Augments the MINORITY class to match the majority class count.
    Applied ONLY to train — val/test stay clean.
    """
    rng = random.Random(seed)

    n_benign  = (train_df["label"] == 0).sum()
    n_attack  = (train_df["label"] == 1).sum()

    if n_benign == n_attack:
        print("   ⚖️  Train split already balanced")
        return train_df

    if n_attack < n_benign:
        minority_label = 1
        minority_name  = "attack"
        gap = n_benign - n_attack
    else:
        minority_label = 0
        minority_name  = "benign"
        gap = n_attack - n_benign

    print(f"   🔄 Augmenting {gap} {minority_name} samples to balance train split...")

    minority_texts = train_df[train_df["label"] == minority_label]["text"].tolist()
    augmented = []
    for i in range(gap):
        src = minority_texts[i % len(minority_texts)]
        aug = augment_text(src, rng)
        augmented.append({"text": aug, "label": minority_label})

    aug_df = pd.DataFrame(augmented)
    result = pd.concat([train_df, aug_df], ignore_index=True)

    new_n0 = (result["label"] == 0).sum()
    new_n1 = (result["label"] == 1).sum()
    print(f"   ✅ Train balanced: {new_n0} benign, {new_n1} attack ({len(result)} total)")

    return result


# ─── Contamination check ─────────────────────────────────────────────────────

def check_contamination(train_df, val_df, test_df):
    """Assert zero exact-text overlap between splits."""
    train_texts = set(train_df["text"].str.lower().str.strip())
    val_texts   = set(val_df["text"].str.lower().str.strip())
    test_texts  = set(test_df["text"].str.lower().str.strip())

    train_val_overlap  = train_texts & val_texts
    train_test_overlap = train_texts & test_texts
    val_test_overlap   = val_texts & test_texts

    if train_val_overlap:
        print(f"   ❌ CONTAMINATION: {len(train_val_overlap)} train/val overlaps!")
    if train_test_overlap:
        print(f"   ❌ CONTAMINATION: {len(train_test_overlap)} train/test overlaps!")
    if val_test_overlap:
        print(f"   ❌ CONTAMINATION: {len(val_test_overlap)} val/test overlaps!")

    total_overlap = len(train_val_overlap) + len(train_test_overlap) + len(val_test_overlap)
    assert total_overlap == 0, (
        f"Split contamination detected! "
        f"train/val={len(train_val_overlap)}, "
        f"train/test={len(train_test_overlap)}, "
        f"val/test={len(val_test_overlap)}"
    )
    print("   ✅ Zero overlap between train/val/test — clean splits")


# ─── Metrics helper ──────────────────────────────────────────────────────────

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    acc  = accuracy_score(labels, preds)
    f1   = f1_score(labels, preds, pos_label=1)
    prec = precision_score(labels, preds, pos_label=1, zero_division=0)
    rec  = recall_score(labels, preds, pos_label=1, zero_division=0)
    return {"accuracy": acc, "f1": f1, "precision": prec, "recall": rec}


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Fine-tune DistilBERT for threat classification")
    parser.add_argument("--epochs",     type=int,   default=10,   help="Training epochs (default: 10)")
    parser.add_argument("--batch-size", type=int,   default=16,   help="Batch size (default: 16)")
    parser.add_argument("--lr",         type=float, default=3e-5, help="Learning rate (default: 3e-5)")
    parser.add_argument("--max-length", type=int,   default=256,  help="Max token length (default: 256)")
    parser.add_argument("--warmup",     type=float, default=0.1,  help="Warmup fraction of total steps (default: 0.1)")
    parser.add_argument("--patience",   type=int,   default=3,    help="Early stopping patience (default: 3)")
    parser.add_argument("--seed",       type=int,   default=42,   help="Random seed (default: 42)")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("🛡️  NEURO-SENTRY — DistilBERT Fine-Tuning (Phase 7)")
    print("=" * 70)

    # ── Device detection ──────────────────────────────────────────────────
    if torch.cuda.is_available():
        device = torch.device("cuda")
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem  = torch.cuda.get_device_properties(0).total_memory / 1e9
        print(f"\n🚀 GPU detected: {gpu_name} ({gpu_mem:.1f} GB VRAM)")
    else:
        device = torch.device("cpu")
        print("\n⚠️  No GPU detected — training on CPU (will be slower)")

    print(f"   Device: {device}")
    print(f"   PyTorch: {torch.__version__}")
    print(f"   CUDA: {torch.version.cuda if torch.cuda.is_available() else 'N/A'}")

    # ── Load dataset ──────────────────────────────────────────────────────
    if not DATASET_FILE.exists():
        print(f"\n❌ Dataset not found at {DATASET_FILE}")
        print("   Run: cd backend && ./venv/bin/python scripts/collect_dataset.py")
        sys.exit(1)

    rows = []
    with open(DATASET_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    df = pd.DataFrame(rows)

    df = df.dropna(subset=["text", "label"])
    df["text"]  = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)
    df = df[df["text"].str.len() >= 5]

    print(f"\n📊 Raw dataset: {len(df)} samples")
    print(f"   Benign (0):    {(df['label'] == 0).sum()} ({(df['label'] == 0).mean():.1%})")
    print(f"   Malicious (1): {(df['label'] == 1).sum()} ({(df['label'] == 1).mean():.1%})")

    # ── 70/15/15 split (BEFORE augmentation) ──────────────────────────────
    train_df, temp_df = train_test_split(
        df, test_size=0.30, random_state=args.seed, stratify=df["label"]
    )
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, random_state=args.seed, stratify=temp_df["label"]
    )

    print(f"\n📂 Split (before augmentation):")
    print(f"   Train: {len(train_df)} (benign={(train_df['label']==0).sum()}, attack={(train_df['label']==1).sum()})")
    print(f"   Val:   {len(val_df)} (benign={(val_df['label']==0).sum()}, attack={(val_df['label']==1).sum()})")
    print(f"   Test:  {len(test_df)} (benign={(test_df['label']==0).sum()}, attack={(test_df['label']==1).sum()})")

    # ── Contamination check ───────────────────────────────────────────────
    print(f"\n🔍 Contamination check...")
    check_contamination(train_df, val_df, test_df)

    # ── Augment train split ONLY ──────────────────────────────────────────
    print(f"\n⚖️  Balancing train split via augmentation...")
    train_df = augment_train_split(train_df, seed=args.seed)

    # Re-check contamination after augmentation
    print(f"🔍 Post-augmentation contamination check...")
    check_contamination(train_df, val_df, test_df)

    # ── Class weights (on augmented train) ────────────────────────────────
    from sklearn.utils.class_weight import compute_class_weight
    class_weights = compute_class_weight(
        class_weight="balanced",
        classes=np.array([0, 1]),
        y=train_df["label"].values,
    )
    class_weights_tensor = torch.tensor(class_weights, dtype=torch.float32)
    print(f"\n⚖️  Class weights: benign={class_weights[0]:.3f}, malicious={class_weights[1]:.3f}")

    # ── Tokenizer ─────────────────────────────────────────────────────────
    print(f"\n📥 Loading tokenizer: {BASE_MODEL}...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    def tokenize(examples):
        return tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=args.max_length,
        )

    train_ds = Dataset.from_pandas(train_df[["text", "label"]].reset_index(drop=True))
    val_ds   = Dataset.from_pandas(val_df[["text", "label"]].reset_index(drop=True))
    test_ds  = Dataset.from_pandas(test_df[["text", "label"]].reset_index(drop=True))

    print("🔤 Tokenizing...")
    train_ds = train_ds.map(tokenize, batched=True, desc="Tokenize train")
    val_ds   = val_ds.map(tokenize, batched=True, desc="Tokenize val")
    test_ds  = test_ds.map(tokenize, batched=True, desc="Tokenize test")

    # ── Model ─────────────────────────────────────────────────────────────
    print(f"\n📥 Loading model: {BASE_MODEL}...")
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=2,
        id2label=LABEL_MAP,
        label2id={"benign": 0, "malicious": 1},
    )

    param_count = sum(p.numel() for p in model.parameters())
    trainable   = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"   Parameters: {param_count / 1e6:.1f}M total, {trainable / 1e6:.1f}M trainable")

    # ── Training args ─────────────────────────────────────────────────────
    output_dir = str(MODEL_DIR / "checkpoints")
    os.makedirs(output_dir, exist_ok=True)

    total_steps = (len(train_ds) // args.batch_size) * args.epochs
    warmup_steps = int(total_steps * args.warmup)

    use_bf16 = False
    use_fp16 = False
    if torch.cuda.is_available():
        if torch.cuda.get_device_capability()[0] >= 8:
            use_bf16 = True
        else:
            use_fp16 = True

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        warmup_steps=warmup_steps,
        weight_decay=0.01,
        bf16=use_bf16,
        fp16=use_fp16,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        logging_steps=50,
        report_to="none",
        seed=args.seed,
        save_total_limit=2,
        dataloader_num_workers=2,
        remove_unused_columns=True,
    )

    # ── Weighted loss Trainer ─────────────────────────────────────────────
    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            import torch.nn as nn
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.logits
            loss_fn = nn.CrossEntropyLoss(
                weight=class_weights_tensor.to(logits.device)
            )
            loss = loss_fn(logits, labels)
            return (loss, outputs) if return_outputs else loss

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        processing_class=tokenizer,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=args.patience)],
    )

    mp_mode = "BF16" if use_bf16 else ("FP16" if use_fp16 else "FP32")
    print(f"\n{'─' * 70}")
    print(f"🏋️  Training Configuration:")
    print(f"   Model:       {BASE_MODEL}")
    print(f"   Train size:  {len(train_ds)} (after augmentation)")
    print(f"   Val size:    {len(val_ds)} (clean, no augmentation)")
    print(f"   Test size:   {len(test_ds)} (held-out, no augmentation)")
    print(f"   Epochs:      {args.epochs}")
    print(f"   Batch size:  {args.batch_size}")
    print(f"   LR:          {args.lr}")
    print(f"   Max length:  {args.max_length}")
    print(f"   Precision:   {mp_mode}")
    print(f"   Patience:    {args.patience} (on val loss)")
    print(f"{'─' * 70}\n")

    start_time = time.time()
    trainer.train()
    elapsed = time.time() - start_time

    print(f"\n⏱️  Training completed in {elapsed / 60:.1f} minutes")

    # ── Evaluate on HELD-OUT TEST set ─────────────────────────────────────
    print(f"\n{'─' * 70}")
    print("📊 HELD-OUT TEST SET EVALUATION")
    print("   ⚠️  Eval on held-out test set (never seen during training)")
    print(f"{'─' * 70}\n")

    test_results = trainer.predict(test_ds)
    test_preds = np.argmax(test_results.predictions, axis=-1)
    test_labels = test_results.label_ids

    acc  = accuracy_score(test_labels, test_preds)
    f1   = f1_score(test_labels, test_preds, pos_label=1)
    prec = precision_score(test_labels, test_preds, pos_label=1, zero_division=0)
    rec  = recall_score(test_labels, test_preds, pos_label=1, zero_division=0)

    cm = confusion_matrix(test_labels, test_preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print(f"   Accuracy:  {acc:.4f}")
    print(f"   F1:        {f1:.4f}")
    print(f"   Precision: {prec:.4f}")
    print(f"   Recall:    {rec:.4f}")
    print(f"   FPR:       {fpr:.4f}")

    print(f"\n📋 Classification Report:")
    print(classification_report(test_labels, test_preds, target_names=["benign", "malicious"]))

    print(f"📊 Confusion Matrix:")
    print(f"   {'':>12} Pred Benign  Pred Malicious")
    print(f"   {'Actual Benign':>15}  {cm[0][0]:>8}   {cm[0][1]:>10}")
    print(f"   {'Actual Malicious':>15}  {cm[1][0]:>8}   {cm[1][1]:>10}")
    print(f"\n   False Positive Rate: {fpr:.2%}")

    # ── Val results for comparison ────────────────────────────────────────
    print(f"\n{'─' * 70}")
    print("📊 Validation Set Results (for comparison):")
    val_results = trainer.evaluate()
    print(f"   Val Loss:      {val_results.get('eval_loss', 0):.4f}")
    print(f"   Val Accuracy:  {val_results.get('eval_accuracy', 0):.4f}")
    print(f"   Val F1:        {val_results.get('eval_f1', 0):.4f}")
    print(f"   Val Precision: {val_results.get('eval_precision', 0):.4f}")
    print(f"   Val Recall:    {val_results.get('eval_recall', 0):.4f}")

    # ── Save model ────────────────────────────────────────────────────────
    save_dir = MODEL_DIR
    print(f"\n💾 Saving model to {save_dir}...")
    os.makedirs(save_dir, exist_ok=True)
    trainer.save_model(str(save_dir))
    tokenizer.save_pretrained(str(save_dir))

    # ── Save metrics ──────────────────────────────────────────────────────
    metrics = {
        "model": BASE_MODEL,
        "dataset_size": len(df),
        "train_size_raw": int((df.shape[0] * 0.7)),
        "train_size_augmented": len(train_ds),
        "val_size": len(val_ds),
        "test_size": len(test_ds),
        "split": "70/15/15",
        "augmentation": "train-only (minority class balancing)",
        "epochs_trained": int(trainer.state.epoch) if trainer.state.epoch else args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.lr,
        "max_length": args.max_length,
        "class_weights": {"benign": float(class_weights[0]), "malicious": float(class_weights[1])},
        "precision_mode": mp_mode,
        "training_time_sec": round(elapsed, 1),
        "contamination_check": "passed",
        "test_metrics": {
            "accuracy": round(acc, 4),
            "f1": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "fpr": round(fpr, 4),
            "confusion_matrix": cm.tolist(),
        },
        "val_metrics": {
            "loss": round(val_results.get("eval_loss", 0), 4),
            "accuracy": round(val_results.get("eval_accuracy", 0), 4),
            "f1": round(val_results.get("eval_f1", 0), 4),
            "precision": round(val_results.get("eval_precision", 0), 4),
            "recall": round(val_results.get("eval_recall", 0), 4),
        },
    }

    metrics_path = save_dir / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"📝 Metrics saved to {metrics_path}")

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print("✅ TRAINING COMPLETE")
    print(f"{'=' * 70}")
    print(f"   Model:            {save_dir}")
    print(f"   Test F1:          {f1:.4f}")
    print(f"   Test Precision:   {prec:.4f}")
    print(f"   Test Recall:      {rec:.4f}")
    print(f"   Test FPR:         {fpr:.2%}")
    print(f"   Training Time:    {elapsed / 60:.1f} min")
    print(f"   Augmentation:     train-only (no leakage)")
    print(f"   Contamination:    passed ✅")

    checks = []
    checks.append(("F1 > 88%", f1 > 0.88))
    checks.append(("Precision > 90%", prec > 0.90))
    checks.append(("FP < 5%", fpr < 0.05))
    all_pass = all(ok for _, ok in checks)

    print(f"\n🎯 Target Metrics:")
    for label, ok in checks:
        print(f"   {label} {'✅' if ok else '❌'}")

    if all_pass:
        print("\n   All targets met! ✅")
    else:
        print("\n   ⚠️  Some targets not met — review training data and parameters")

    print()


if __name__ == "__main__":
    main()
