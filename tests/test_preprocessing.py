"""
Tests for Data Preprocessing Module (modules/preprocessing.py)
"""

import numpy as np
import pandas as pd
import pytest
from modules.preprocessing import clean_column_names, clean_label_string, clean_dataset, prepare_features_for_inference

def test_clean_column_names():
    df = pd.DataFrame({" Flow Duration ": [100], "Destination Port   ": [80]})
    cleaned = clean_column_names(df)
    assert list(cleaned.columns) == ["Flow Duration", "Destination Port"]

def test_clean_label_string():
    assert clean_label_string("BENIGN") == "Benign"
    assert clean_label_string("DDoS") == "DDoS"
    assert clean_label_string("FTP-Patator") == "Brute Force (FTP)"
    assert clean_label_string("SSH-Patator") == "Brute Force (SSH)"
    assert clean_label_string("DoS Hulk") == "DoS (Hulk)"
    # Test unicode artifact removal
    assert clean_label_string("Web Attack \ufffd\ufffd Brute Force") == "Web Attack (Brute Force)"

def test_clean_dataset_inf_nan_handling():
    data = {
        "Flow Duration": [100.0, np.inf, 300.0, -np.inf],
        "Flow Bytes/s": [10.0, np.nan, 30.0, 40.0],
        "Label": ["BENIGN", "DDoS", "BENIGN", "PortScan"]
    }
    df = pd.DataFrame(data)
    cleaned_df, stats = clean_dataset(df, target_column="Label")
    
    assert stats["inf_values_replaced"] == 2
    assert not np.isinf(cleaned_df["Flow Duration"].values).any()
    assert not cleaned_df["Flow Bytes/s"].isna().any()
    assert cleaned_df["Label"].iloc[0] == "Benign"

def test_prepare_features_for_inference():
    expected_feats = ["Flow Duration", "Total Fwd Packets", "Destination Port"]
    df = pd.DataFrame({
        "Flow Duration": [150],
        "Total Fwd Packets": [3],
        "Label": ["DDoS"] # Target label present
    })
    X, missing = prepare_features_for_inference(df, expected_feats)
    
    assert "Label" not in X.columns # Prevent data leakage
    assert list(X.columns) == expected_feats
    assert "Destination Port" in missing
    assert X["Destination Port"].iloc[0] == 0.0 # Imputed missing column
