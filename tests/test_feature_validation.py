"""
Tests for Feature Validation Module (modules/feature_validation.py)
"""

import pandas as pd
import pytest
from modules.feature_validation import validate_dataset_schema

def test_validate_empty_dataset():
    df = pd.DataFrame()
    report = validate_dataset_schema(df, expected_features=["col1", "col2"])
    assert report["is_valid"] is False
    assert report["compatibility_status"] == "Empty"

def test_validate_compatible_schema():
    expected = ["Flow Duration", "Total Fwd Packets", "Protocol"]
    df = pd.DataFrame({
        "Flow Duration": [100],
        "Total Fwd Packets": [2],
        "Protocol": [6]
    })
    report = validate_dataset_schema(df, expected)
    assert report["is_valid"] is True
    assert report["compatibility_status"] == "Compatible"
    assert report["match_ratio"] == 1.0

def test_validate_incompatible_schema():
    expected = ["Flow Duration", "Total Fwd Packets", "Protocol", "Fwd Packet Length Max", "Bwd Packet Length Max"]
    # Only 1 matching column out of 5 (20%)
    df = pd.DataFrame({
        "Flow Duration": [100],
        "Username": ["admin"],
        "IP Address": ["192.168.1.1"]
    })
    report = validate_dataset_schema(df, expected)
    assert report["is_valid"] is False
    assert "Incompatible" in report["compatibility_status"]
