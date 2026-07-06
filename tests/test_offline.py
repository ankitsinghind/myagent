import sys
import os

# Ensure root and src directories are in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

sys.stdout.reconfigure(encoding='utf-8')
from src import agents

# Resolve absolute path to the test emails folder
test_email_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test_emails', 'test5_wipro_internship_fraud.txt')
email = open(test_email_path, encoding='utf-8').read()

print("=== OFFLINE Keyword Fraud Analysis: Wipro Internship Email ===")
result = agents._keyword_fraud_fallback(email)
print(f"Suspicious  : {result['is_suspicious']}")
print(f"Confidence  : {result['confidence_score']*100:.0f}%")
print(f"Threat Type : {result['threat_type']}")
print("Red Flags:")
for flag in result['red_flags']:
    print(f"  -> {flag}")

print()
print("=== OFFLINE Regex IOC Extraction: Wipro Internship Email ===")
iocs = agents._regex_fallback_extract(email)
print(f"IPs     : {iocs['ips']}")
print(f"Domains : {iocs['domains']}")
print(f"URLs    : {iocs['urls']}")
