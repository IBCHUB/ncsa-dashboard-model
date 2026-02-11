
import sys
import os
import logging

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.classifier import classify_threat

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_hybrid_pipeline():
    test_cases = [
        {
            "text": "The LockBit ransomware encrypted all critical servers and demanded 10 BTC.",
            "expected_lang": "en",
            "expected_type": "Ransomware"
        },
        {
            "text": "มีการตรวจพบการโจมตีแบบ Phishing โดยการส่งอีเมลปลอมที่อ้างว่าเป็นธนาคาร",
            "expected_lang": "th",
            "expected_type": "Phishing"
        },
        {
            "text": "Hackers utilized a zero-day exploit in the VPN gateway to gain access.",
            "expected_lang": "en",
            "expected_type": "Zero-day Exploit"
        }
    ]

    print("=== Testing Hybrid Pipeline ===")
    for case in test_cases:
        print(f"\nInput: {case['text'][:50]}...")
        try:
            result = classify_threat(case['text'])
            print(f"Detected Language: {result.get('language')}")
            print(f"Model Used: {result.get('model_used')}")
            print(f"Threat Types: {result.get('threat_types')}")
            print(f"Confidence: {result.get('confidence')}")
            
            # Simple assertions
            if case['expected_lang'] in result.get('language', ''):
                print("✅ Language Correct")
            else:
                print(f"❌ Language Mismatch (Expected {case['expected_lang']})")
                
            if case['expected_type'] in result.get('threat_types', []):
                print("✅ Threat Type Correct")
            else:
                print(f"❌ Threat Type Mismatch (Expected {case['expected_type']})")

        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("NOTE: Ensure you have installed requirements: pip install -r requirements.txt")
    test_hybrid_pipeline()
