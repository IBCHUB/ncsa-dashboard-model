"""
Simulate Massive Cyber Attack (Stress Test)
Generates a large dataset of realistic IOCs to stress test BART-Large and Prophet.
"""

import json
import random
from datetime import datetime, timedelta
import os

OUTPUT_FILE = "data_lake/simulation_attack.json"

# Threat Scenarios
SCENARIOS = {
    "ransomware_outbreak": {
        "description_templates": [
            "LockBit 3.0 ransomware detected encrypting {target} servers via {method}.",
            "New execution of BlackCat ransomware observed in {target} sector.",
            "Ransom note found on {target} endpoint, demanding BTC payment to {wallet}.",
            "File extension .encrypted detected, likely {variant} ransomware activity."
        ],
        "types": ["Ransomware", "Malware"],
        "actors": ["LockBit", "BlackCat", "Conti", "Play"],
        "targets": ["Financial", "Healthcare", "Government", "Energy"]
    },
    "apt_campaign": {
        "description_templates": [
            "APT29 utilizing {tool} for lateral movement in {target} network.",
            "Sophisticated spear-phishing campaign by {actor} targeting {target} diplomats.",
            "C2 beaconing detected to {ip} on port 443, associated with {actor}.",
            "Zero-day exploit in Exchange Server used by {actor} for initial access."
        ],
        "types": ["APT", "Phishing", "C2", "Exploit"],
        "actors": ["APT29", "Lazarus", "APT41", "Sandworm"],
        "targets": ["Government", "Defense", "Think Tanks"]
    },
    "ddos_botnet": {
        "description_templates": [
            "Massive UDP flood targeting {target} web portal from {count} IPs.",
            "Mirai botnet variant scanning for open telnet ports on {target} IoT devices.",
            "DDoS attack volume 50Gbps observed against {target} infrastructure.",
            "Botnet C2 comms detected at {ip} controlling zombie nodes."
        ],
        "types": ["DDoS", "Botnet"],
        "actors": ["Mirai", "Anonymous", "Killnet"],
        "targets": ["Banking", "ISP", "E-commerce"]
    }
}

def generate_ioc(index: int, date: datetime, scenario_name: str) -> dict:
    scenario = SCENARIOS[scenario_name]
    template = random.choice(scenario["description_templates"])
    
    # Fill template
    desc = template.format(
        target=random.choice(scenario["targets"]),
        method=random.choice(["RDP", "VPN", "Phishing", "SMB"]),
        wallet="bc1q" + "".join(random.choices("abcdef0123456789", k=20)),
        variant=random.choice(scenario["actors"]),
        actor=random.choice(scenario["actors"]),
        tool=random.choice(["Cobalt Strike", "Mimikatz", "PowerShell"]),
        ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        count=random.randint(100, 5000)
    )
    
    return {
        "ioc": {
            "value": f"192.168.{random.randint(10,99)}.{index}",
            "type": "ip"
        },
        "params": {
            "source": f"simulation_{scenario_name}",
            "confidence": random.randint(50, 90)
        },
        "description": desc,
        "collect_time": date.isoformat() + "Z",
        "event_time": date.isoformat() + "Z",
        "created_at": date.isoformat() + "Z",
        "enrichment": {
            "geo": {
                "country": random.choice(["TH", "US", "CN", "RU", "VN", "SG"])
            }
        }
    }

def main():
    print("🚀 Generating stress test data...")
    records = []
    
    # Generate 30-day increasing trend (Heavy Load)
    base_date = datetime.now() - timedelta(days=30)
    
    for day in range(31):
        current_date = base_date + timedelta(days=day)
        
        # Increasing volume: Day 1 = 5 events, Day 30 = ~50 events
        # Total approx 800-900 events
        daily_volume = 5 + int(day * 1.5) + random.randint(-2, 5)
        
        # Mix scenarios
        for i in range(daily_volume):
            # Weighted random choice of scenarios
            scenario = random.choices(
                ["ransomware_outbreak", "apt_campaign", "ddos_botnet"],
                weights=[0.5, 0.3, 0.2]  # Mostly Ransomware
            )[0]
            
            records.append(generate_ioc(len(records), current_date, scenario))
            
    print(f"Generated {len(records)} IOCs.")
    
    # Ensure directory exists
    os.makedirs("data_lake", exist_ok=True)
    
    # Save
    with open(OUTPUT_FILE, "w") as f:
        json.dump(records, f, indent=2)
        
    print(f"Saved to {OUTPUT_FILE}")
    print("\nNext command to run:")
    print("python ai-service/scripts/ingest.py --data-dir data_lake")

if __name__ == "__main__":
    main()
