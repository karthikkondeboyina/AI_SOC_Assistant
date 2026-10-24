"""
AI SOC Assistant - Threat Detection Module
Loads the trained Random Forest pipeline, executes batch network flow inference,
computes prediction confidence, and flags suspicious activity.
"""

from typing import Dict, Any, List, Tuple, Optional
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from config.settings import MODEL_FILE, METADATA_FILE
from modules.preprocessing import prepare_features_for_inference
from modules.feature_validation import validate_dataset_schema

# Singleton cache for model and metadata
_CACHED_PIPELINE = None
_CACHED_METADATA = None

def load_threat_model() -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """
    Loads and caches the trained ML pipeline and its associated metadata.
    Returns (pipeline, metadata) or (None, None) if not trained yet.
    """
    global _CACHED_PIPELINE, _CACHED_METADATA
    
    if _CACHED_PIPELINE is not None and _CACHED_METADATA is not None:
        return _CACHED_PIPELINE, _CACHED_METADATA
        
    if not MODEL_FILE.exists() or not METADATA_FILE.exists():
        return None, None
        
    try:
        pipeline = joblib.load(MODEL_FILE)
        with open(METADATA_FILE, "r", encoding="utf-8") as f:
            metadata = json.load(f)
            
        _CACHED_PIPELINE = pipeline
        _CACHED_METADATA = metadata
        return _CACHED_PIPELINE, _CACHED_METADATA
    except Exception as e:
        print(f"[-] Error loading model: {e}")
        return None, None

def is_model_available() -> bool:
    """Check if model files exist on disk."""
    return MODEL_FILE.exists() and METADATA_FILE.exists()

def detect_threats(
    df: pd.DataFrame,
    confidence_threshold: float = 0.50
) -> Tuple[Optional[pd.DataFrame], Dict[str, Any]]:
    """
    Runs threat classification across an input network traffic DataFrame.
    
    Returns:
        results_df: DataFrame augmented with 'predicted_class', 'confidence', 'is_suspicious'
        summary: Diagnostic statistics (total rows, suspicious count, class breakdown)
    """
    pipeline, metadata = load_threat_model()
    if pipeline is None or metadata is None:
        return None, {
            "error": "ML Model is not trained. Please train the model via training/train_model.py first."
        }
        
    expected_features = metadata.get("feature_names", [])
    
    # 1. Validate Schema Compatibility
    validation = validate_dataset_schema(df, expected_features)
    if not validation["is_valid"]:
        return None, {
            "error": f"Dataset schema validation failed: {validation['message']}",
            "validation_details": validation
        }
        
    # 2. Prepare Features for Model
    X, missing_cols = prepare_features_for_inference(df, expected_features)
    
    # 3. Predict Classes and Probabilities
    try:
        predictions = pipeline.predict(X)
        has_proba = hasattr(pipeline, "predict_proba")
        if has_proba:
            probabilities = pipeline.predict_proba(X)
            confidences = np.max(probabilities, axis=1)
        else:
            confidences = np.ones(len(predictions))
    except Exception as exc:
        return None, {
            "error": f"Prediction error: {str(exc)}"
        }
        
    # 4. Construct Output DataFrame
    results_df = df.copy()
    results_df["predicted_class"] = predictions
    results_df["confidence"] = np.round(confidences, 4)
    results_df["is_suspicious"] = results_df["predicted_class"].apply(
        lambda c: str(c).strip().lower() != "benign"
    )
    
    # 5. Generate Summary Diagnostics
    class_counts = results_df["predicted_class"].value_counts().to_dict()
    suspicious_count = int(results_df["is_suspicious"].sum())
    total_count = len(results_df)
    
    summary = {
        "total_records": total_count,
        "benign_count": total_count - suspicious_count,
        "suspicious_count": suspicious_count,
        "suspicious_percentage": round((suspicious_count / total_count) * 100, 2) if total_count > 0 else 0,
        "class_breakdown": class_counts,
        "model_version": metadata.get("model_version", "1.0.0"),
        "features_imputed": len(missing_cols),
        "mean_confidence": float(np.mean(confidences)) if len(confidences) > 0 else 0.0
    }
    
    return results_df, summary
