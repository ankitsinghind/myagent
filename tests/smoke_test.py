import sys
import os
import json

# Ensure root and src directories are in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

sys.stdout.reconfigure(encoding='utf-8')

from dotenv import load_dotenv
load_dotenv()

from src import agents

test_email = (
    "From: CEO <boss@gmail.com>\n"
    "Subject: Urgent Wire Transfer\n"
    "I need you to send $5000 to a new vendor immediately. Keep it secret."
)

print("Running SentinelSOC pipeline on test email...\n")
for r in agents.analyze_incident_stream(test_email):
    d = json.loads(r)
    event = d.get("event")
    msg = d.get("message", "")
    agent = d.get("agent", "")
    if event == "agent_start":
        print(f"\n[START] {agent}: {msg}")
    elif event == "agent_log":
        print(f"  • [{agent}] {msg[:120]}")
    elif event == "agent_complete":
        print(f"  ✓ [{agent}] {msg}")
    elif event == "complete":
        print(f"\n[COMPLETE] Severity: {d.get('severity')}")
        print(f"[COMPLETE] Fraud: {d.get('fraud_assessment', {}).get('threat_type')} | Suspicious: {d.get('fraud_assessment', {}).get('is_suspicious')}")
        actions = d.get("actions", {})
        for k, v in actions.items():
            print(f"  • {k}: [{v['status']}] {v['desc']}")
