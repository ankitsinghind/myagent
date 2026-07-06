import json
import time
import os
import sys
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load secure environment configuration
load_dotenv()

# Reconfigure stdout to use UTF-8 on Windows consoles to prevent encoding exceptions
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure root and src directories are in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from src import agents

# Setup CLI terminal colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"
COLOR_GREY = "\033[90m"

# Define the evaluation test suite
TEST_CASES = [
    {
        "id": "TC-001",
        "name": "PayPal Phishing (Homoglyph & ZW)",
        "input": "From: PayPal Support <security@pa\u0443\u0440al-security.com>\nSubject: Urgent: Action required on your account\nWe detected a suspicious login attempt. Please confirm your credentials immediately to avoid suspension: hxxps[:]//verify-paypal-login[.]com/login.\nIP remote: 198.51.100.42",
        "expected_suspicious": True,
        "expected_threat_type": "Phishing",
        "expected_severity": "CRITICAL",
        "expected_ips": ["198.51.100.42"],
        "expected_domains": ["verify-paypal-login.com"],
        "expected_urls": ["https://verify-paypal-login.com/login."]
    },
    {
        "id": "TC-002",
        "name": "BEC CEO Transfer Lure",
        "input": "From: Chief Executive Officer <ceo.internal.comms@gmail.com>\nSubject: CONFIDENTIAL: Urgent Wire Transfer\nI am in a board meeting right now and need you to transfer $15,000 to a new vendor immediately. Please do not call to confirm as my phone is off. Keep this confidential.",
        "expected_suspicious": True,
        "expected_threat_type": "BEC",
        "expected_severity": "CRITICAL",
        "expected_ips": [],
        "expected_domains": [],
        "expected_urls": []
    },
    {
        "id": "TC-003",
        "name": "Clean Project Update",
        "input": "From: Sarah Jenkins <sjenkins@company.com>\nSubject: Project Roadmap Update Q3\nHi Team, here is the updated project roadmap for Q3. We are on track for the July release. Let me know if you have any questions.",
        "expected_suspicious": False,
        "expected_threat_type": "None",
        "expected_severity": "LOW",
        "expected_ips": [],
        "expected_domains": [],
        "expected_urls": []
    },
    {
        "id": "TC-004",
        "name": "Obfuscated Postal Fraud",
        "input": "From: Postal Express <tracking-post\u200bal-delivery.com>\nSubject: Delivery Failure: Action Required\nYour package could not be delivered due to an incorrect address. Update details here: hxxps://track-postal-delivery-update[.]com/auth and pay a small fee of $0.50.",
        "expected_suspicious": True,
        "expected_threat_type": "Phishing",
        "expected_severity": "CRITICAL",
        "expected_ips": [],
        "expected_domains": ["track-postal-delivery-update.com"],
        "expected_urls": ["https://track-postal-delivery-update.com/auth"]
    }
]

def calculate_precision_recall(extracted: List[str], expected: List[str]) -> tuple[float, float]:
    """Calculates precision and recall for extracted IOCs."""
    ext_set = set([x.lower().strip().replace("[", "").replace("]", "") for x in extracted])
    exp_set = set([x.lower().strip().replace("[", "").replace("]", "") for x in expected])
    
    if not exp_set and not ext_set:
        return 1.0, 1.0
    if not exp_set and ext_set:
        return 0.0, 1.0
    if exp_set and not ext_set:
        return 1.0, 0.0
        
    true_positives = len(ext_set.intersection(exp_set))
    false_positives = len(ext_set - exp_set)
    false_negatives = len(exp_set - ext_set)
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    
    return precision, recall

def run_evaluations():
    print(f"{COLOR_BOLD}{COLOR_CYAN}=================================================={COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}   SentinelSOC Automated Evaluation Benchmark     {COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}   (Day 4: Security, Robustness & Agent Evals)   {COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}=================================================={COLOR_RESET}\n")
    
    results = []
    total_latency = 0.0
    total_cost = 0.0
    passed_cases = 0
    
    for case in TEST_CASES:
        print(f"[*] Running {COLOR_BOLD}{case['name']}{COLOR_RESET} ({case['id']})...")
        
        start_time = time.time()
        
        severity = "LOW"
        fraud_suspicious = False
        fraud_threat_type = "None"
        extracted_ips = []
        extracted_domains = []
        extracted_urls = []
        agent_hops = []
        trace_metrics = {}
        
        try:
            for step_str in agents.analyze_incident_stream(case["input"]):
                step = json.loads(step_str)
                event = step.get("event")
                
                if event == "agent_start":
                    agent_name = step.get("agent")
                    agent_hops.append(agent_name)
                    
                elif event == "agent_log":
                    agent_name = step.get("agent")
                    msg = step.get("message")
                    if agent_name == "extraction_agent":
                        if msg.startswith("-> Identified IP address:"):
                            extracted_ips.append(msg.split(": ")[1].strip())
                        elif msg.startswith("-> Identified Domain:"):
                            extracted_domains.append(msg.split(": ")[1].strip())
                        elif msg.startswith("-> Identified URL:"):
                            extracted_urls.append(msg.split(": ")[1].strip())
                            
                elif event == "complete":
                    severity = step.get("severity", "LOW")
                    fraud_result = step.get("fraud_assessment", {})
                    fraud_suspicious = fraud_result.get("is_suspicious", False)
                    fraud_threat_type = fraud_result.get("threat_type", "None")
                    trace_metrics = step.get("trace_metrics", {})
        except Exception as e:
            print(f"{COLOR_RED}[Error] Pipeline failed to execute: {e}{COLOR_RESET}")
            results.append({
                "id": case["id"],
                "name": case["name"],
                "status": "FAILED (Execution Error)",
                "latency": time.time() - start_time,
                "cost": 0.0,
                "classification_acc": 0.0,
                "ioc_precision": 0.0,
                "ioc_recall": 0.0,
                "trajectory_ok": False
            })
            continue
            
        latency = time.time() - start_time
        total_latency += latency
        
        class_ok = (fraud_suspicious == case["expected_suspicious"])
        if class_ok and case["expected_suspicious"]:
            class_ok = (fraud_threat_type.lower() == case["expected_threat_type"].lower())
            
        class_score = 1.0 if class_ok else 0.0
        
        ip_p, ip_r = calculate_precision_recall(extracted_ips, case["expected_ips"])
        dom_p, dom_r = calculate_precision_recall(extracted_domains, case["expected_domains"])
        url_p, url_r = calculate_precision_recall(extracted_urls, case["expected_urls"])
        
        avg_precision = (ip_p + dom_p + url_p) / 3.0
        avg_recall = (ip_r + dom_r + url_r) / 3.0
        
        requires_intel = len(case["expected_ips"]) > 0 or len(case["expected_domains"]) > 0
        run_intel = "threat_intel_agent" in agent_hops
        
        requires_sandbox = len(case["expected_urls"]) > 0
        run_sandbox = "sandbox_agent" in agent_hops
        
        trajectory_ok = True
        if requires_intel and not run_intel:
            trajectory_ok = False
        if requires_sandbox and not run_sandbox:
            trajectory_ok = False
            
        case_cost = sum([metrics.get("cost", 0.0) for metrics in trace_metrics.values()])
        total_cost += case_cost
        
        passed = class_ok and (avg_precision >= 0.8) and (avg_recall >= 0.8) and trajectory_ok and (severity == case["expected_severity"])
        
        status_str = f"{COLOR_GREEN}PASSED{COLOR_RESET}" if passed else f"{COLOR_RED}FAILED{COLOR_RESET}"
        if passed:
            passed_cases += 1
            
        print(f"  +- Status: {status_str} | Latency: {latency:.2f}s | Cost: ${case_cost:.5f}")
        
        results.append({
            "id": case["id"],
            "name": case["name"],
            "status": "PASSED" if passed else "FAILED",
            "latency": latency,
            "cost": case_cost,
            "classification_acc": class_score,
            "ioc_precision": avg_precision,
            "ioc_recall": avg_recall,
            "trajectory_ok": trajectory_ok
        })
        print("-" * 50)
        time.sleep(2.0)
        
    print("\n" + "=" * 80)
    print(f"{COLOR_BOLD}{COLOR_CYAN}{'BENCHMARK SUMMARY REPORT CARD':^80}{COLOR_RESET}")
    print("=" * 80)
    
    headers = f"{'Case ID':<8} | {'Scenario Name':<28} | {'Status':<8} | {'Classify':<8} | {'IOC P/R':<10} | {'Trace OK':<8} | {'Cost ($)':<8}"
    print(headers)
    print("-" * 80)
    
    for r in results:
        status_color = COLOR_GREEN if r["status"] == "PASSED" else COLOR_RED
        status_lbl = f"{status_color}{r['status']:<8}{COLOR_RESET}"
        
        ioc_str = f"{r['ioc_precision']*100:.0f}%/{r['ioc_recall']*100:.0f}%"
        trace_lbl = "YES" if r["trajectory_ok"] else "NO"
        cost_str = f"${r['cost']:.5f}" if r["cost"] > 0 else "$0.00"
        
        print(f"{r['id']:<8} | {r['name']:<28} | {status_lbl} | {r['classification_acc']*100:>6.0f}% | {ioc_str:<10} | {trace_lbl:<8} | {cost_str:<8}")
        
    print("-" * 80)
    success_rate = (passed_cases / len(TEST_CASES)) * 100
    rate_color = COLOR_GREEN if success_rate >= 80 else (COLOR_YELLOW if success_rate >= 50 else COLOR_RED)
    
    print(f"Overall Success Rate      : {rate_color}{success_rate:.1f}% ({passed_cases}/{len(TEST_CASES)} cases passed){COLOR_RESET}")
    print(f"Total Benchmark Latency   : {total_latency:.2f} seconds")
    print(f"Total Cumulative API Cost : ${total_cost:.5f}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    run_evaluations()
