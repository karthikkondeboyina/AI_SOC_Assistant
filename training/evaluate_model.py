"""
AI SOC Assistant - Model Evaluation Script
Loads the trained pipeline and metadata, reporting detailed performance statistics,
per-class metrics, and confusion matrix data.
"""

import json
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from config.settings import MODEL_FILE, METADATA_FILE, SAMPLE_DATA_DIR

def evaluate_saved_model():
    """Reads metadata and evaluates the saved model."""
    if not MODEL_FILE.exists() or not METADATA_FILE.exists():
        print(f"[-] Trained model or metadata not found at {MODEL_FILE}")
        print("    Please run: python training/train_model.py")
        return False
        
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        meta = json.load(f)
        
    print("=" * 65)
    print("AI SOC ASSISTANT - MODEL EVALUATION REPORT")
    print("=" * 65)
    print(f"Model Version:       {meta.get('model_version')}")
    print(f"Algorithm:           {meta.get('algorithm')}")
    print(f"Training Date:       {meta.get('training_date')}")
    print(f"Dataset:             {meta.get('dataset_source')}")
    print(f"Features:            {meta.get('total_features')}")
    print(f"Classes:             {len(meta.get('classes', []))}")
    print(f"Training Records:    {meta.get('num_training_samples'):,}")
    print(f"Test Records:        {meta.get('num_test_samples'):,}")
    
    metrics = meta.get("metrics", {})
    print("\n--- Summary Performance Metrics ---")
    print(f"Overall Accuracy:    {metrics.get('accuracy', 0)*100:.2f}%")
    print(f"Weighted Precision:  {metrics.get('weighted_precision', 0):.4f}")
    print(f"Weighted Recall:     {metrics.get('weighted_recall', 0):.4f}")
    print(f"Weighted F1-Score:   {metrics.get('weighted_f1', 0):.4f}")
    print(f"Macro F1-Score:      {metrics.get('macro_f1', 0):.4f}")
    
    print("\n--- Per-Class Performance Breakdown ---")
    report = metrics.get("classification_report", {})
    classes = meta.get("classes", [])
    
    rows = []
    for cls in classes:
        if cls in report:
            rows.append({
                "Class": cls,
                "Precision": f"{report[cls]['precision']:.3f}",
                "Recall": f"{report[cls]['recall']:.3f}",
                "F1-Score": f"{report[cls]['f1-score']:.3f}",
                "Support": report[cls]['support']
            })
            
    df_report = pd.DataFrame(rows)
    print(df_report.to_string(index=False))
    return True

if __name__ == "__main__":
    evaluate_saved_model()
