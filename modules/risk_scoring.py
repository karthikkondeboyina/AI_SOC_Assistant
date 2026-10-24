"""
AI SOC Assistant - Explainable Risk Scoring Module
Calculates a transparent, multi-factor risk score (0-100) and severity rating
for detected network events based on attack category, confidence, flow characteristics,
and asset criticality.
"""

from typing import Dict, Any, Union
import numpy as np
from config.settings import BASE_SEVERITY_SCORES

# Asset Criticality multipliers
ASSET_CRITICALITY_MULTIPLIERS = {
    "Low": 0.85,
    "Standard": 1.0,
    "High": 1.15,
    "Mission-Critical": 1.30
}

def get_severity_label(score: float) -> str:
    """Categorizes a numerical risk score (0-100) into a qualitative severity tier."""
    if score >= 85:
        return "Critical"
    elif score >= 70:
        return "High"
    elif score >= 45:
        return "Medium"
    elif score > 15:
        return "Low"
    else:
        return "Informational"

def calculate_risk_score(
    predicted_class: str,
    confidence: float,
    flow_features: Dict[str, Any] = None,
    asset_criticality: str = "Standard"
) -> Dict[str, Any]:
    """
    Computes an explainable risk score (0-100) with contributing factors.
    
    Formula:
      If class is Benign: Risk = 0
      Raw Risk = (Base_Attack_Severity * 0.60) + (Confidence * 100 * 0.25) + (Volume_Impact * 0.15)
      Final Risk = clamp(Raw Risk * Asset_Multiplier, 0, 100)
    """
    flow_features = flow_features or {}
    pred_clean = str(predicted_class).strip()
    
    # If classified as Benign, minimal risk unless confidence is unusually low
    if pred_clean.lower() == "benign":
        return {
            "risk_score": 0.0,
            "severity": "Benign",
            "base_score": 0.0,
            "confidence_factor": round(confidence * 100, 1),
            "volume_factor": 0.0,
            "asset_multiplier": ASSET_CRITICALITY_MULTIPLIERS.get(asset_criticality, 1.0),
            "explanation": "Traffic classified as normal benign network activity. No elevated risk detected."
        }
        
    # 1. Base Attack Severity (0-100)
    base_score = float(BASE_SEVERITY_SCORES.get(pred_clean, 60.0))
    
    # 2. Confidence Component (0-100)
    conf_clamped = min(1.0, max(0.0, float(confidence)))
    conf_component = conf_clamped * 100.0
    
    # 3. Flow Volume / Anomaly Impact (0-100)
    # Checks packet rate or flow duration
    volume_factor = 20.0 # Default baseline flow impact
    fwd_pkts = float(flow_features.get("Total Fwd Packets", flow_features.get("total_fwd_packets", 0)))
    flow_bytes_s = float(flow_features.get("Flow Bytes/s", flow_features.get("flow_bytes/s", 0)))
    
    if fwd_pkts > 1000 or flow_bytes_s > 1_000_000:
        volume_factor = 85.0
    elif fwd_pkts > 100 or flow_bytes_s > 100_000:
        volume_factor = 60.0
    elif fwd_pkts > 10:
        volume_factor = 40.0
        
    # 4. Asset Criticality Multiplier
    asset_mult = ASSET_CRITICALITY_MULTIPLIERS.get(asset_criticality, 1.0)
    
    # Calculate Weighted Raw Score
    raw_score = (base_score * 0.60) + (conf_component * 0.25) + (volume_factor * 0.15)
    adjusted_score = raw_score * asset_mult
    final_score = float(np.clip(np.round(adjusted_score, 1), 0.0, 100.0))
    
    severity = get_severity_label(final_score)
    
    explanation = (
        f"Base attack weight for '{pred_clean}' ({base_score:.0f} pts, 60% weight); "
        f"ML confidence of {conf_clamped*100:.1f}% ({conf_component*0.25:.1f} pts, 25% weight); "
        f"traffic volume impact ({volume_factor*0.15:.1f} pts, 15% weight); "
        f"Asset criticality multiplier: {asset_mult}x."
    )
    
    return {
        "risk_score": final_score,
        "severity": severity,
        "base_score": base_score,
        "confidence_factor": round(conf_component, 1),
        "volume_factor": volume_factor,
        "asset_multiplier": asset_mult,
        "explanation": explanation
    }

def batch_calculate_risk(
    predictions_df,
    asset_criticality: str = "Standard"
):
    """
    Appends 'risk_score', 'severity', and 'risk_explanation' columns to a predictions DataFrame.
    """
    scores = []
    severities = []
    explanations = []
    
    for _, row in predictions_df.iterrows():
        p_class = row.get("predicted_class", "Benign")
        conf = row.get("confidence", 0.9)
        
        flow_feats = {
            "Total Fwd Packets": row.get("Total Fwd Packets", 0),
            "Flow Bytes/s": row.get("Flow Bytes/s", 0)
        }
        
        res = calculate_risk_score(
            predicted_class=p_class,
            confidence=conf,
            flow_features=flow_feats,
            asset_criticality=asset_criticality
        )
        scores.append(res["risk_score"])
        severities.append(res["severity"])
        explanations.append(res["explanation"])
        
    res_df = predictions_df.copy()
    res_df["risk_score"] = scores
    res_df["severity"] = severities
    res_df["risk_explanation"] = explanations
    return res_df
