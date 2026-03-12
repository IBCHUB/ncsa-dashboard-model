"""
Verify the active classifier model.
"""

import sys
import logging
from datetime import datetime
from pathlib import Path

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.append(str(AI_SERVICE_ROOT))

from models.classifier import classify_threat

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

if __name__ == "__main__":
    verify_classification()
