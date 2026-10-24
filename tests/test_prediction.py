"""
Tests for Threat Detection Inference (modules/threat_detection.py)
"""

import pandas as pd
import pytest
from modules.threat_detection import is_model_available, load_threat_model, detect_threats

def test_model_presence():
    assert is_model_available() is True
    pipeline, meta = load_threat_model()
    assert pipeline is not None
    assert meta is not None
    assert "metrics" in meta
    assert len(meta.get("feature_names", [])) == 77

def test_threat_detection_sample():
    pipeline, meta = load_threat_model()
    expected_feats = meta["feature_names"]
    
    # Create synthetic test rows matching expected features
    test_data = {f: [0.0, 10.0] for f in expected_feats}
    test_df = pd.DataFrame(test_data)
    
    res_df, summary = detect_threats(test_df)
    assert res_df is not None
    assert "predicted_class" in res_df.columns
    assert "confidence" in res_df.columns
    assert "is_suspicious" in res_df.columns
    assert summary["total_records"] == 2
