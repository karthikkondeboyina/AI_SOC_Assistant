"""
AI SOC Assistant - Feature Validation Module
Validates uploaded cybersecurity datasets against the schema expected by the trained ML model.
Rejects incompatible files with descriptive diagnostics.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
from modules.preprocessing import clean_column_names

def validate_dataset_schema(
    df: pd.DataFrame,
    expected_features: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Validates a dataset's structure, column presence, and compatibility.
    
    Args:
        df: The pandas DataFrame to validate.
        expected_features: List of column names expected by the ML model.
        
    Returns:
        Validation report dictionary with status, scores, and recommendations.
    """
    if df is None:
        return {
            "is_valid": False,
            "compatibility_status": "Invalid",
            "message": "No dataset was provided for validation.",
            "match_ratio": 0.0
        }
        
    if df.empty:
        return {
            "is_valid": False,
            "compatibility_status": "Empty",
            "message": "Uploaded dataset is completely empty (0 rows).",
            "match_ratio": 0.0
        }
        
    cleaned_df = clean_column_names(df)
    current_columns = set(cleaned_df.columns)
    
    # If no expected features provided (e.g. model not yet loaded), check generic network-flow features
    if not expected_features:
        # Check basic flow characteristics
        has_numeric = len(cleaned_df.select_dtypes(include=["number"]).columns) > 0
        return {
            "is_valid": has_numeric,
            "compatibility_status": "Unverified (Model Not Loaded)",
            "message": f"Dataset contains {len(cleaned_df)} rows and {len(cleaned_df.columns)} columns.",
            "match_ratio": 1.0 if has_numeric else 0.0,
            "total_columns": len(cleaned_df.columns)
        }
        
    expected_set = set(expected_features)
    # Ignore label column in user dataset during inference compatibility check
    user_cols_no_label = {c for c in current_columns if c.lower() not in ["label", "attack", "class"]}
    
    matched = list(user_cols_no_label.intersection(expected_set))
    missing = list(expected_set - user_cols_no_label)
    extra = list(user_cols_no_label - expected_set)
    
    match_ratio = len(matched) / len(expected_features) if expected_features else 0.0
    
    if match_ratio >= 0.95:
        status = "Compatible"
        is_valid = True
        msg = f"Dataset is fully compatible ({len(matched)} of {len(expected_features)} model features matched)."
    elif match_ratio >= 0.60:
        status = "Partially Compatible"
        is_valid = True
        msg = (
            f"Dataset matches {len(matched)} of {len(expected_features)} features ({match_ratio*100:.1f}%). "
            f"{len(missing)} missing features will be imputed with zeros during analysis."
        )
    else:
        status = "Incompatible Schema"
        is_valid = False
        msg = (
            f"Dataset does not match the required network-flow schema. Only {len(matched)} of "
            f"{len(expected_features)} features matched ({match_ratio*100:.1f}%). "
            "Please upload a standard CIC-IDS2017 network traffic dataset."
        )
        
    return {
        "is_valid": is_valid,
        "compatibility_status": status,
        "match_ratio": match_ratio,
        "matched_count": len(matched),
        "total_expected": len(expected_features),
        "missing_features": missing[:10], # Truncate for display
        "extra_features": extra[:10],
        "message": msg
    }
