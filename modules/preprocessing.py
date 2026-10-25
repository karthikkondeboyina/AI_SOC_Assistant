"""
AI SOC Assistant - Preprocessing Module
Handles data cleaning, normalization of column names, replacement of infinite/NaN values,
and standardization of attack labels for both training and real-time inference.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd
from config.settings import LABEL_MAPPING

def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """
    Strips leading/trailing whitespace from column names and normalizes spacing.
    CIC-IDS2017 often contains inconsistent whitespace in headers.
    """
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    return df

def clean_label_string(label: Any) -> str:
    """
    Cleans label string by removing non-ASCII artifacts (e.g., \ufffd in Web Attacks)
    and normalizing casing.
    """
    if pd.isna(label):
        return "Unknown"
    
    label_str = str(label)
    # Remove unicode replacement characters or non-breaking spaces
    clean = label_str.encode("ascii", "ignore").decode().strip()
    # Normalize multiple spaces
    clean = " ".join(clean.split())
    # Match against dictionary or uppercase comparison
    upper_clean = clean.upper()
    for raw_key, standard_val in LABEL_MAPPING.items():
        if upper_clean == raw_key or upper_clean == standard_val.upper():
            return standard_val
            
    # Fuzzy match common CIC-IDS2017 variations
    if "BENIGN" in upper_clean:
        return "Benign"
    elif "DDOS" in upper_clean:
        return "DDoS"
    elif "PORT" in upper_clean and "SCAN" in upper_clean:
        return "Port Scan"
    elif "BOT" in upper_clean:
        return "Botnet"
    elif "FTP" in upper_clean:
        return "Brute Force (FTP)"
    elif "SSH" in upper_clean:
        return "Brute Force (SSH)"
    elif "HULK" in upper_clean:
        return "DoS (Hulk)"
    elif "GOLDENEYE" in upper_clean:
        return "DoS (GoldenEye)"
    elif "SLOWLORIS" in upper_clean:
        return "DoS (Slowloris)"
    elif "SLOWHTTPTEST" in upper_clean:
        return "DoS (SlowHTTPTest)"
    elif "HEARTBLEED" in upper_clean:
        return "Vulnerability Exploit (Heartbleed)"
    elif "INFILTRATION" in upper_clean:
        return "Infiltration"
    elif "SQL" in upper_clean:
        return "Web Attack (SQL Injection)"
    elif "XSS" in upper_clean:
        return "Web Attack (XSS)"
    elif "BRUTE" in upper_clean:
        return "Web Attack (Brute Force)"

    return clean if clean else "Unknown"

def clean_dataset(
    df: pd.DataFrame,
    target_column: Optional[str] = None
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Applies comprehensive cleaning:
    1. Strips column whitespaces
    2. Identifies and cleans target label if present
    3. Replaces +/- infinity with NaN
    4. Imputes NaNs in numerical columns with medians
    5. Deduplicates records if necessary
    """
    stats: Dict[str, Any] = {
        "original_rows": len(df),
        "original_cols": len(df.columns),
        "inf_values_replaced": 0,
        "nan_values_imputed": 0,
        "duplicates_removed": 0
    }
    
    cleaned_df = clean_column_names(df)
    
    # Locate label column if not explicitly supplied
    detected_target = target_column
    if detected_target is None:
        for candidate in ["Label", "label", "LABEL", "Attack", "class", "Class"]:
            if candidate in cleaned_df.columns:
                detected_target = candidate
                break
                
    if detected_target and detected_target in cleaned_df.columns:
        uniq_labels = cleaned_df[detected_target].dropna().unique()
        label_map = {lbl: clean_label_string(lbl) for lbl in uniq_labels}
        cleaned_df[detected_target] = cleaned_df[detected_target].map(label_map).fillna("Unknown")
        
    # Isolate numerical features
    num_cols = cleaned_df.select_dtypes(include=[np.number]).columns.tolist()
    if detected_target in num_cols:
        num_cols.remove(detected_target)
        
    # Replace inf and -inf
    inf_mask = np.isinf(cleaned_df[num_cols].values)
    stats["inf_values_replaced"] = int(np.sum(inf_mask))
    cleaned_df[num_cols] = cleaned_df[num_cols].replace([np.inf, -np.inf], np.nan)
    
    # Count missing values before imputation
    nan_count = int(cleaned_df[num_cols].isna().sum().sum())
    stats["nan_values_imputed"] = nan_count
    
    # Impute missing values with column median (fallback to 0 if all are nan)
    medians = cleaned_df[num_cols].median()
    cleaned_df[num_cols] = cleaned_df[num_cols].fillna(medians.fillna(0))
    
    stats["cleaned_rows"] = len(cleaned_df)
    stats["target_column"] = detected_target
    return cleaned_df, stats

def prepare_features_for_inference(
    df: pd.DataFrame,
    expected_features: list
) -> Tuple[pd.DataFrame, list]:
    """
    Prepares an uploaded DataFrame for model inference:
    1. Normalizes column names
    2. Drops target/label column if present (prevents leakage)
    3. Aligns columns strictly to the expected feature list in a single vectorized reindex
    4. Rapidly replaces inf/nan values using C-level NumPy nan_to_num
    Returns feature matrix (X) and list of missing columns if any.
    """
    cleaned_df = clean_column_names(df)
    
    # Prevent leakage: remove any label/class columns
    for label_col in ["Label", "label", "LABEL", "Attack", "class", "Class"]:
        if label_col in cleaned_df.columns:
            cleaned_df = cleaned_df.drop(columns=[label_col])
            
    # Check for missing features
    missing_cols = [col for col in expected_features if col not in cleaned_df.columns]
    
    # Fast reindex: populates missing columns with 0.0 in one shot
    X = cleaned_df.reindex(columns=expected_features, fill_value=0.0)
    
    # Fast NumPy in-place cleanup of inf/nan
    X_vals = X.to_numpy(dtype=np.float32, copy=True)
    np.nan_to_num(X_vals, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    X = pd.DataFrame(X_vals, columns=expected_features, index=cleaned_df.index)
    
    return X, missing_cols

