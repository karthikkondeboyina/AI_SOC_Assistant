"""
AI SOC Assistant - Machine Learning Training Script
Trains a robust, leakage-resistant Random Forest Classifier on genuine CIC-IDS2017 network traffic.
Saves the trained pipeline and comprehensive model metadata.
"""

import json
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support, confusion_matrix
import joblib

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config.settings import (
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    SAMPLE_DATA_DIR,
    MODELS_DIR,
    MODEL_FILE,
    METADATA_FILE,
    MODEL_VERSION
)
from modules.preprocessing import clean_dataset, clean_label_string

def sample_balanced_dataset(raw_dir: Path, max_per_class: int = 15000) -> pd.DataFrame:
    """
    Samples from all raw CIC-IDS2017 parquet files to build a balanced dataset
    containing all attack classes and representative benign traffic.
    """
    parquet_files = sorted(raw_dir.glob("*.parquet"))
    if not parquet_files:
        raise FileNotFoundError(f"No parquet files found in {raw_dir}")
        
    print(f"[*] Found {len(parquet_files)} CIC-IDS2017 raw files. Loading and sampling...")
    collected_dfs = []
    
    for p_file in parquet_files:
        print(f"    - Reading {p_file.name}...")
        df_chunk = pd.read_parquet(p_file)
        
        # Strip column names
        df_chunk.columns = [c.strip() for c in df_chunk.columns]
        
        # Standardize labels
        if "Label" in df_chunk.columns:
            df_chunk["Label"] = df_chunk["Label"].apply(clean_label_string)
            
            # Sample per class within this file
            sampled_chunks = []
            for label, group in df_chunk.groupby("Label"):
                if len(group) > max_per_class:
                    sampled_chunks.append(group.sample(n=max_per_class, random_state=42))
                else:
                    sampled_chunks.append(group)
            collected_dfs.append(pd.concat(sampled_chunks, axis=0))
            
    combined = pd.concat(collected_dfs, axis=0).reset_index(drop=True)
    print(f"[+] Total combined records before final balancing: {len(combined):,}")
    print("    Class distribution:")
    print(combined["Label"].value_counts())
    
    # Final cap on over-represented classes (especially Benign)
    final_chunks = []
    for label, group in combined.groupby("Label"):
        if len(group) > max_per_class:
            final_chunks.append(group.sample(n=max_per_class, random_state=42))
        else:
            final_chunks.append(group)
            
    final_df = pd.concat(final_chunks, axis=0).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return final_df

def train_and_save_pipeline():
    """Main training routine."""
    print("=" * 65)
    print("AI SOC ASSISTANT - MODEL TRAINING PIPELINE")
    print("=" * 65)
    
    # 1. Load and sample data
    df = sample_balanced_dataset(RAW_DATA_DIR, max_per_class=12000)
    
    # 2. Clean dataset (inf, nan, whitespace)
    print("\n[*] Preprocessing and cleaning dataset...")
    cleaned_df, stats = clean_dataset(df, target_column="Label")
    print(f"    Infinities replaced: {stats['inf_values_replaced']}")
    print(f"    NaNs imputed: {stats['nan_values_imputed']}")
    
    # 3. Export a clean sample CSV for user testing in Streamlit
    sample_test_df = cleaned_df.sample(n=min(1000, len(cleaned_df)), random_state=42)
    sample_csv_path = SAMPLE_DATA_DIR / "sample_soc_traffic.csv"
    sample_test_df.to_csv(sample_csv_path, index=False)
    print(f"[+] Saved sample test CSV for dashboard upload at: {sample_csv_path}")
    
    # 4. Separate features and target
    target_col = "Label"
    feature_cols = [c for c in cleaned_df.columns if c != target_col]
    X = cleaned_df[feature_cols]
    y = cleaned_df[target_col]
    
    print(f"\n[*] Total training features: {len(feature_cols)}")
    print(f"[*] Total dataset records: {len(X):,}")
    
    # 5. Train / Test Split (Stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"    Train records: {len(X_train):,}")
    print(f"    Test records:  {len(X_test):,}")
    
    # 6. Build Scikit-Learn Pipeline
    print("\n[*] Initializing Pipeline (StandardScaler + RandomForestClassifier)...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced_subsample"
        ))
    ])
    
    # 7. Train Model
    print("[*] Training Random Forest model...")
    pipeline.fit(X_train, y_train)
    print("[+] Training completed successfully.")
    
    # 8. Evaluate on Unseen Test Split
    print("\n[*] Evaluating on unseen test set...")
    y_pred = pipeline.predict(X_test)
    y_pred_proba = pipeline.predict_proba(X_test)
    
    acc = float(accuracy_score(y_test, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
    
    clf_report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    classes = pipeline.named_steps["classifier"].classes_.tolist()
    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()
    
    print(f"\n[+] Model Evaluation Results:")
    print(f"    Accuracy:          {acc*100:.2f}%")
    print(f"    Macro F1-Score:    {f1_macro:.4f}")
    print(f"    Weighted F1-Score: {f1_weighted:.4f}")
    
    # 9. Save Serialized Pipeline
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_FILE, compress=3)
    print(f"[+] Serialized model saved to: {MODEL_FILE}")
    
    # 10. Save Model Metadata
    metadata = {
        "model_version": MODEL_VERSION,
        "algorithm": "RandomForestClassifier with StandardScaler",
        "training_date": datetime.now().isoformat(),
        "dataset_source": "CIC-IDS2017 Benchmark Dataset (UNB)",
        "num_training_samples": len(X_train),
        "num_test_samples": len(X_test),
        "total_features": len(feature_cols),
        "feature_names": feature_cols,
        "classes": classes,
        "metrics": {
            "accuracy": acc,
            "macro_precision": float(p_macro),
            "macro_recall": float(r_macro),
            "macro_f1": float(f1_macro),
            "weighted_precision": float(p_weighted),
            "weighted_recall": float(r_weighted),
            "weighted_f1": float(f1_weighted),
            "classification_report": clf_report,
            "confusion_matrix": cm
        }
    }
    
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Model metadata saved to: {METADATA_FILE}")
    print("\n[SUCCESS] Phase 4 Training Complete!")

if __name__ == "__main__":
    train_and_save_pipeline()
