"""
Verify AI Model Upgrades
Run this script inside the container to verify the configured classifier model and Prophet.
"""

import sys
import os
import logging
from datetime import datetime, timedelta

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.classifier import classify_threat
from models.trend_predictor import predict_trends

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verifier")

def verify_classification():
    print("\n" + "="*50)
    print("🤖 TESTING CLASSIFICATION (Zero-shot MNLI)")
    print("="*50)
    
    # Test Case: Semantic understanding (not just keywords)
    # A simple keyword search might miss "exfiltration" if we don't use that exact word,
    # but BART should understand "sending sensitive data out".
    text = "The attacker established persistence via registry keys and began piping sensitive database content to an external IP address."
    
    print(f"Input Text: \"{text}\"")
    print("Analyzing...")
    
    start_time = datetime.now()
    result = classify_threat(text)
    duration = (datetime.now() - start_time).total_seconds()
    
    print(f"Time taken: {duration:.2f}s")
    print(f"Confidence: {result['confidence']}")
    print(f"Detected Labels: {result['threat_types']}")
    
    # Validation logic
    expected_concepts = ['exfiltration', 'data_breach', 'persistence']
    detected = [t.lower().replace(' ', '_') for t in result['threat_types']]
    
    # Check if any expected concepts match (loose matching because labels might vary)
    # Our labels are: Ransomware, Phishing, Malware, Data Breach, DDoS, APT, Defacement, Vulnerability, Botnet, C2, Credential Theft, Other
    # "Piping sensitive content" -> Data Breach
    
    if "Data Breach" in result['threat_types'] or "APT" in result['threat_types']:
        print("✅ SUCCESS: Model correctly identified the threat context.")
    else:
        print("⚠️ WARNING: Model might have missed the context. Check labels above.")

def verify_forecasting():
    print("\n" + "="*50)
    print("🔮 TESTING FORECASTING (Facebook Prophet)")
    print("="*50)
    
    # Generate synthetic data: 14 days of increasing threats
    events = []
    base_date = datetime.now() - timedelta(days=14)
    
    print("Generating 14 days of synthetic data...")
    for i in range(14):
        date_str = (base_date + timedelta(days=i)).isoformat()
        # Create 'i' events for this day (linear increase: 1, 2, 3...)
        # Prophet should pick up this trend easily
        count = i + 5 
        for _ in range(count):
            events.append({
                "event_time": date_str,
                "aiThreatTypes": ["Ransomware"]
            })
            
    print(f"Generated {len(events)} events.")
    print("Running prediction...")
    
    try:
        start_time = datetime.now()
        result = predict_trends(events)
        duration = (datetime.now() - start_time).total_seconds()
        
        print(f"Time taken: {duration:.2f}s")
        
        # Check model used
        model_used = result.get('model_used', 'unknown')
        print(f"Model Engine: {model_used}")
        
        if model_used == 'prophet':
            print("✅ SUCCESS: Facebook Prophet is active and running.")
        else:
            print("❌ FAILURE: Falling back to Linear Regression (Prophet not valid).")
            
        # Check prediction direction
        # We fed increasing data, so it should say "increasing"
        predictions = result.get('predictions', [])
        if predictions:
            ransomware_pred = next((p for p in predictions if p['threat_type'] == 'Ransomware'), None)
            if ransomware_pred:
                print(f"Prediction for Ransomware: {ransomware_pred['direction']} (Slope: {ransomware_pred['slope']})")
                if ransomware_pred['direction'] == 'increasing':
                    print("✅ SUCCESS: Trend correctly identified as INCREASING.")
                else:
                    print("⚠️ WARNING: Trend detection mismatch.")
    except Exception as e:
        print(f"❌ ERROR: Prediction crashed - {e}")

if __name__ == "__main__":
    verify_classification()
    verify_forecasting()
