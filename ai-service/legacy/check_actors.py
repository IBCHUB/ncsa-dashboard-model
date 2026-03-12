import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
file_path = REPO_ROOT / 'legacy' / 'dashboard-poc' / 'public' / 'data' / 'normalized_iocs.json'

try:
    with open(file_path, 'r') as f:
        data = json.load(f)

    events = data.get('events', [])
    events_with_actors = 0
    all_actors = {}

    for event in events:
        actors = event.get('aiThreatActors', [])
        if actors:
            events_with_actors += 1
            for actor in actors:
                all_actors[actor] = all_actors.get(actor, 0) + 1

    print(f"Total events processed: {len(events)}")
    print(f"Events with extracted threat actors: {events_with_actors}")
    
    if all_actors:
        print("\nExtracted Threat Actors (Count):")
        for actor, count in sorted(all_actors.items(), key=lambda x: x[1], reverse=True):
            print(f"- {actor}: {count}")
    else:
        print("\nNo threat actors found in any event.")

except Exception as e:
    print(f"Error reading file: {e}")
