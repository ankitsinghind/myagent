import os
import sys
import argparse
import json
import time
import subprocess
from datetime import datetime
from dotenv import load_dotenv

# Reconfigure stdout to use UTF-8 on Windows consoles to prevent encoding exceptions
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Load secure environment configuration
load_dotenv()

# Ensure root and src folders are in the system path for local packages
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src import agents
from src.utils.metrics import print_observability_summary

# Mode selector: True = local Windows systems modifications, False = simulated enterprise configs (default)
LOCAL_SYSTEM_MODE = False

# ANSI Terminal Colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"
COLOR_GREY = "\033[90m"

def print_banner(use_color: bool):
    banner = """
==================================================
   SentinelSOC Multi-Agent Security Analyzer
==================================================
    """
    if use_color:
        print(f"{COLOR_BOLD}{COLOR_CYAN}{banner.strip()}{COLOR_RESET}\n")
    else:
        print(banner.strip() + "\n")

def add_windows_firewall_rule(ip: str) -> bool:
    try:
        if ip in ["127.0.0.1", "0.0.0.0", "localhost"]:
            print("Error: Cannot block loopback/local address.")
            return False
            
        rule_name = f"SentinelSOC Block {ip}"
        cmd = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Outbound -Action Block -RemoteAddress {ip}'
        ps_cmd = ["powershell", "-Command", cmd]
        res = subprocess.run(ps_cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return True
        else:
            sys.stderr.write(f"Firewall execution output: {res.stderr}\n")
            return False
    except Exception as e:
        sys.stderr.write(f"Failed to add firewall rule: {e}\n")
        return False

def add_hosts_sinkhole(domain: str) -> bool:
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8") as f:
                content = f.read()
            if f"127.0.0.1 {domain}" in content:
                print(f"Domain {domain} is already mapped in hosts.")
                return True
                
        with open(hosts_path, "a", encoding="utf-8") as f:
            f.write(f"\n127.0.0.1 {domain} # SentinelSOC Sinkhole\n")
        return True
    except PermissionError:
        sys.stderr.write("Permission denied: Modifying the hosts file requires Administrator privileges.\n")
        return False
    except Exception as e:
        sys.stderr.write(f"Failed to update hosts file: {e}\n")
        return False


def run_analyst_shell(report_markdown: str, trace_metrics: dict, actions: dict, use_color: bool):
    shell_title = "SentinelSOC Interactive Security Console"
    c_blue = COLOR_CYAN if use_color else ""
    c_bold = COLOR_BOLD if use_color else ""
    c_reset = COLOR_RESET if use_color else ""
    
    print(f"{c_bold}{c_blue}{'=' * 50}{c_reset}")
    print(f"{c_bold}{c_blue}{shell_title.center(50)}{c_reset}")
    print(f"{c_bold}{c_blue}{'=' * 50}{c_reset}")
    print("Type 'help' for available commands. Type 'exit' to quit.\n")
    
    history = []
    context = report_markdown
    
    while True:
        try:
            prompt_str = f"{c_bold}SentinelSOC > {c_reset}"
            cmd = input(prompt_str).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting interactive shell.")
            break
            
        if not cmd:
            continue
            
        cmd_lower = cmd.lower()
        
        if cmd_lower == "exit":
            print("Session closed.")
            break
            
        elif cmd_lower == "help":
            print("Available Commands:")
            print("  help                       - Show this help message.")
            print("  show report                - View the full Incident Response playbook report.")
            print("  show metrics               - View Day 5 LLM Observability details.")
            print("  status                     - Show current mitigation playbook action statuses.")
            print("  block ip <ip>              - Execute firewall containment block rule (HITL).")
            print("  block domain <domain>      - Execute DNS sinkhole block rule (HITL).")
            print("  ask <question>             - Ask a question to the lead agent team (multi-turn).")
            print("  exit                       - Exit the interactive console.")
            print()
            
        elif cmd_lower == "show report":
            print("\n--- INCIDENT RESPONSE PLAYBOOK ---")
            print(report_markdown)
            print("--- END OF PLAYBOOK ---\n")
            
        elif cmd_lower == "show metrics":
            print_observability_summary(trace_metrics, use_color)
            
        elif cmd_lower == "status":
            print("\nMitigation Action Statuses:")
            for action, act in actions.items():
                print(f"  • {action.capitalize():10} : [{act.get('status', 'INACTIVE')}] - {act.get('desc', '')}")
            print()
            
        elif cmd_lower.startswith("block ip"):
            parts = cmd.split(" ")
            if len(parts) < 3:
                print("Error: Please specify the IP address. Usage: block ip <ip>")
                continue
            ip = parts[2].strip()
            if LOCAL_SYSTEM_MODE:
                confirm = input(f"Confirm firewall block rule for IP '{ip}'? (yes/no): ").strip().lower()
                if confirm in ["yes", "y"]:
                    print(f"[*] Executing Windows Defender Firewall containment block for IP: {ip}...")
                    success = add_windows_firewall_rule(ip)
                    if success:
                        actions["firewall"] = {"status": "BLOCKED", "desc": f"IP rule BLOCKED at perimeter firewall for IP: {ip}"}
                        print(f"✓ Rule active: Local firewall successfully blocked inbound/outbound connections for {ip}.")
                    else:
                        print(f"[-] Execution failed. (Make sure you are running as Administrator to apply system changes).")
                else:
                    print("Action cancelled.")
            else:
                print(f"[*] Generating enterprise perimeter firewall policy rule for IP: {ip}...")
                palo_alto_rule = (
                    f"set rulebase security rules \"SentinelSOC-Block-{ip}\" "
                    f"source any destination {ip} service any action deny log-start yes"
                )
                print(f"\n{COLOR_CYAN}--- Palo Alto Networks CLI Config ---{COLOR_RESET}")
                print(palo_alto_rule)
                print(f"{COLOR_CYAN}------------------------------------{COLOR_RESET}\n")
                
                confirm = input("Deploy rule to simulated Enterprise perimeter gateway? (yes/no): ").strip().lower()
                if confirm in ["yes", "y"]:
                    print(f"[*] Pushing security policy payload to corporate perimeter firewall...")
                    time.sleep(1.5)
                    actions["firewall"] = {"status": "DEPLOYED", "desc": f"Deny rule pushed to perimeter security base for IP: {ip}"}
                    print("✓ Status: DEPLOYED. Perimeter firewall policy is active.")
                else:
                    print("Action cancelled.")
                
        elif cmd_lower.startswith("block domain"):
            parts = cmd.split(" ")
            if len(parts) < 3:
                print("Error: Please specify the Domain. Usage: block domain <domain>")
                continue
            domain = parts[2].strip()
            if LOCAL_SYSTEM_MODE:
                confirm = input(f"Confirm local DNS hosts sinkhole block rule for domain '{domain}'? (yes/no): ").strip().lower()
                if confirm in ["yes", "y"]:
                    print(f"[*] Appending DNS sinkhole entry for {domain} to local system hosts file...")
                    success = add_hosts_sinkhole(domain)
                    if success:
                        actions["dns"] = {"status": "SINKHOLED", "desc": f"DNS requests SINKHOLED for domain: {domain}"}
                        print(f"✓ Rule active: Domain {domain} mapped to 127.0.0.1 in local hosts resolver.")
                    else:
                        print(f"[-] Execution failed. (Hosts file write requires Administrator privileges).")
                else:
                    print("Action cancelled.")
            else:
                print(f"[*] Generating DNS core sinkhole policy zone for domain: {domain}...")
                unbound_zone = (
                    f"local-zone: \"{domain}\" redirect\n"
                    f"local-data: \"{domain} A 127.0.0.1\""
                )
                print(f"\n{COLOR_CYAN}--- Unbound/BIND DNS Block Zone Configuration ---{COLOR_RESET}")
                print(unbound_zone)
                print(f"{COLOR_CYAN}------------------------------------------------{COLOR_RESET}\n")
                
                confirm = input("Push zone block to simulated Enterprise DNS resolver? (yes/no): ").strip().lower()
                if confirm in ["yes", "y"]:
                    print(f"[*] Pushing RPZ zone updates to core enterprise nameservers...")
                    time.sleep(1.5)
                    actions["dns"] = {"status": "DEPLOYED", "desc": f"DNS RPZ Sinkhole active for domain: {domain}"}
                    print("✓ Status: DEPLOYED. DNS Sinkhole policy is active.")
                else:
                    print("Action cancelled.")
                
        elif cmd_lower.startswith("ask "):
            question = cmd[4:].strip()
            if not question:
                print("Error: Please type a question.")
                continue
            print("[*] Consulting Lead Incident Liaison agent...")
            followup = agents.chat_follow_up(question, history, context)
            liaison_text = followup.get("text", "No response received.")
            metrics = followup.get("metrics", {})
            
            print(f"\n{c_bold}🤖 [Liaison Agent]{c_reset} {liaison_text}\n")
            
            cost = metrics.get("cost", 0.0)
            cost_str = f"${cost:.5f}" if cost > 0 else "$0.00"
            c_grey = COLOR_GREY if use_color else ""
            print(f"{c_grey}(Liaison turn: {metrics.get('duration', 0.0):.2f}s | prompt tokens: {metrics.get('input_tokens', 0)} | completion tokens: {metrics.get('output_tokens', 0)} | Cost: {cost_str}){c_reset}\n")
            
            history.append({"role": "user", "text": question})
            history.append({"role": "model", "text": liaison_text})
            
            if "liaison_chat" not in trace_metrics:
                trace_metrics["liaison_chat"] = {"duration": 0.0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
            trace_metrics["liaison_chat"]["duration"] += metrics.get("duration", 0.0)
            trace_metrics["liaison_chat"]["input_tokens"] += metrics.get("input_tokens", 0)
            trace_metrics["liaison_chat"]["output_tokens"] += metrics.get("output_tokens", 0)
            trace_metrics["liaison_chat"]["cost"] += cost
            
        else:
            print(f"Unknown command: '{cmd}'. Type 'help' for assistance.")

def main():
    parser = argparse.ArgumentParser(
        description="SentinelSOC Command Line Interface - Multi-Agent Incident Response & Threat Intelligence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples of Use:
  1. Analyze a log file:
     python src/main.py test_emails/test1_paypal_phishing.txt
  
  2. Pipe input directly:
     cat auth.log | python src/main.py -o security_report.md
     
  3. Interactive input:
     python src/main.py
        """
    )
    
    parser.add_argument(
        "file",
        nargs="?",
        type=str,
        help="Path to the file containing incident text (logs, emails, alerts)."
    )
    parser.add_argument(
        "-i", "--input-text",
        type=str,
        help="Direct raw text string of the incident to analyze."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Custom output file path to save the generated Markdown report."
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color rendering in terminal logs."
    )
    parser.add_argument(
        "--local-system",
        action="store_true",
        help="Opt-in to modify local Windows Firewall and hosts file (requires Admin privileges) instead of simulating enterprise perimeter blocks."
    )
    
    args = parser.parse_args()
    
    global LOCAL_SYSTEM_MODE
    LOCAL_SYSTEM_MODE = args.local_system
    
    use_color = not args.no_color and sys.stdout.isatty()
    
    print_banner(use_color)
    
    incident_text = ""
    
    if args.input_text:
        incident_text = args.input_text
        print(f"{COLOR_GREY if use_color else ''}[*] Reading incident details directly from command line...{COLOR_RESET if use_color else ''}")
        
    elif args.file:
        file_path = args.file
        if not os.path.exists(file_path):
            print(f"{COLOR_RED if use_color else ''}[Error] File not found: {file_path}{COLOR_RESET if use_color else ''}", file=sys.stderr)
            sys.exit(1)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                incident_text = f.read()
            print(f"{COLOR_GREY if use_color else ''}[*] Reading incident log from file: {file_path} ({len(incident_text)} characters)...{COLOR_RESET if use_color else ''}")
        except Exception as e:
            print(f"{COLOR_RED if use_color else ''}[Error] Failed to read file: {e}{COLOR_RESET if use_color else ''}", file=sys.stderr)
            sys.exit(1)
            
    elif not sys.stdin.isatty():
        print(f"{COLOR_GREY if use_color else ''}[*] Reading incident data from stdin stream...{COLOR_RESET if use_color else ''}")
        incident_text = sys.stdin.read()
        
    else:
        print(f"{COLOR_BOLD if use_color else ''}Interactive SOC Analyst Mode.{COLOR_RESET if use_color else ''}")
        print("Please paste or type the security logs, alert emails, or incident details below.")
        print(f"{COLOR_GREY if use_color else ''}(To finish, press Enter, then Ctrl+D on Unix or Ctrl+Z on Windows, then Enter):{COLOR_RESET if use_color else ''}\n")
        
        lines = []
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                lines.append(line)
        except KeyboardInterrupt:
            print("\nAnalysis aborted by user.")
            sys.exit(0)
            
        incident_text = "".join(lines)
        print()
        
    if not incident_text.strip():
        print(f"{COLOR_RED if use_color else ''}[Error] Incident description is empty. Nothing to analyze.{COLOR_RESET if use_color else ''}", file=sys.stderr)
        sys.exit(1)
        
    report_markdown = ""
    severity = "LOW"
    actions = {}
    fraud_result = {}
    trace_metrics = {}
    
    try:
        for step_str in agents.analyze_incident_stream(incident_text):
            step = json.loads(step_str)
            event = step.get("event")
            
            if event == "start":
                msg = step.get("message")
                print(f"[*] {msg}")
                
            elif event == "agent_start":
                agent_name = step.get("agent")
                msg = step.get("message")
                c = COLOR_CYAN if use_color else ""
                print(f"\n{c}🤖 [Agent: {agent_name}]{COLOR_RESET if use_color else ''} {msg}")
                
            elif event == "agent_log":
                agent_name = step.get("agent")
                msg = step.get("message")
                
                if agent_name == "fraud_moderator_agent":
                    if "Suspicious:" in msg:
                        parts = msg.split(" | ")
                        susp_part = parts[0]
                        conf_part = parts[1]
                        type_part = parts[2]
                        
                        susp_val = susp_part.split(": ")[1]
                        conf_val = conf_part.split(": ")[1]
                        type_val = type_part.split(": ")[1]
                        
                        if use_color:
                            c_susp = f"{COLOR_BOLD}{COLOR_RED}TRUE{COLOR_RESET}" if "TRUE" in susp_val else f"{COLOR_BOLD}{COLOR_GREEN}FALSE{COLOR_RESET}"
                            c_conf = f"{COLOR_YELLOW}{conf_val}{COLOR_RESET}"
                            c_type = f"{COLOR_BOLD}{COLOR_RED}{type_val}{COLOR_RESET}" if type_val != "None" else f"{COLOR_BOLD}{COLOR_GREEN}None{COLOR_RESET}"
                            print(f"  » Suspicious Check : {c_susp}")
                            print(f"  » Confidence Level : {c_conf}")
                            print(f"  » Target Threat Type: {c_type}")
                        else:
                            print(f"  » Suspicious Check : {susp_val}")
                            print(f"  » Confidence Level : {conf_val}")
                            print(f"  » Target Threat Type: {type_val}")
                        continue
                    elif "-> Red Flag:" in msg:
                        flag_content = msg.split("-> Red Flag: ")[1]
                        if use_color:
                            print(f"    {COLOR_RED}🚩 [Red Flag]{COLOR_RESET} {flag_content}")
                        else:
                            print(f"    🚩 [Red Flag] {flag_content}")
                        continue
                    elif "⚠️" in msg:
                        if use_color:
                            print(f"    {COLOR_YELLOW}⚠️ [Obfuscation]{COLOR_RESET} {msg.replace('⚠️ ', '')}")
                        else:
                            print(f"    ⚠️ [Obfuscation] {msg.replace('⚠️ ', '')}")
                        continue
                
                prefix = "  •"
                colored_msg = msg
                if use_color:
                    if "🔴" in msg or "malicious" in msg.lower() or "block" in msg.lower():
                        prefix = f"  {COLOR_RED}•{COLOR_RESET}"
                        colored_msg = f"{COLOR_RED}{msg}{COLOR_RESET}"
                    elif "🟡" in msg or "suspicious" in msg.lower() or "warning" in msg.lower():
                        prefix = f"  {COLOR_YELLOW}•{COLOR_RESET}"
                        colored_msg = f"{COLOR_YELLOW}{msg}{COLOR_RESET}"
                    elif "🟢" in msg or "clean" in msg.lower():
                        prefix = f"  {COLOR_GREEN}•{COLOR_RESET}"
                        colored_msg = f"{COLOR_GREEN}{msg}{COLOR_RESET}"
                    else:
                        prefix = f"  {COLOR_GREY}•{COLOR_RESET}"
                print(f"{prefix} {colored_msg}")
                
            elif event == "agent_complete":
                agent_name = step.get("agent")
                msg = step.get("message")
                c = COLOR_GREEN if use_color else ""
                print(f"{c}✓ [Agent: {agent_name}] {msg}{COLOR_RESET if use_color else ''}")
                
            elif event == "complete":
                severity = step.get("severity", "LOW")
                actions = step.get("actions", {})
                report_markdown = step.get("report", "")
                fraud_result = step.get("fraud_assessment", {})
                trace_metrics = step.get("trace_metrics", {})
                print(f"\n[*] {step.get('message', 'Incident Mitigation complete.')}")
                
    except Exception as e:
        print(f"\n{COLOR_RED if use_color else ''}[Fatal Error] Agent pipeline failed: {e}{COLOR_RESET if use_color else ''}", file=sys.stderr)
        sys.exit(1)
        
    print("\n" + "=" * 50)
    summary_title = "SECURITY MITIGATION & ASSESSMENT COMPLETE"
    if use_color:
        print(f"{COLOR_BOLD}{COLOR_CYAN}{summary_title.center(50)}{COLOR_RESET}")
    else:
        print(summary_title.center(50))
    print("=" * 50)
    
    sev_str = severity
    if use_color:
        if severity == "CRITICAL":
            sev_str = f"{COLOR_BOLD}{COLOR_RED}CRITICAL{COLOR_RESET}"
        elif severity == "SUSPICIOUS":
            sev_str = f"{COLOR_BOLD}{COLOR_YELLOW}SUSPICIOUS{COLOR_RESET}"
        else:
            sev_str = f"{COLOR_BOLD}{COLOR_GREEN}LOW / SAFE{COLOR_RESET}"
            
    print(f"Overall Calculated Threat Severity: {sev_str}")
    
    if fraud_result:
        susp = fraud_result.get("is_suspicious", False)
        type_val = fraud_result.get("threat_type", "None")
        conf_val = fraud_result.get("confidence_score", 0.0)
        
        susp_str = "TRUE" if susp else "FALSE"
        if use_color:
            susp_str = f"{COLOR_BOLD}{COLOR_RED}TRUE{COLOR_RESET}" if susp else f"{COLOR_BOLD}{COLOR_GREEN}FALSE{COLOR_RESET}"
            type_str = f"{COLOR_BOLD}{COLOR_RED}{type_val}{COLOR_RESET}" if type_val != "None" else f"{COLOR_BOLD}{COLOR_GREEN}None{COLOR_RESET}"
            conf_str = f"{COLOR_YELLOW}{conf_val*100:.1f}%{COLOR_RESET}"
        else:
            type_str = str(type_val)
            conf_str = f"{conf_val*100:.1f}%"
            
        print(f"Fraud Detection Result             : Suspicious={susp_str} | Threat={type_str} | Conf={conf_str}")
        
    print("-" * 50)
    print("Automated Response Action Plan:")
    
    for action_type, act in actions.items():
        status = act.get("status", "INACTIVE")
        desc = act.get("desc", "No recommendations")
        
        status_label = status
        if use_color:
            if status in ["BLOCKED", "QUARANTINED", "SINKHOLED"]:
                status_label = f"{COLOR_BOLD}{COLOR_RED}{status}{COLOR_RESET}"
            elif status in ["MONITOR", "ALERTED", "WATCHED"]:
                status_label = f"{COLOR_BOLD}{COLOR_YELLOW}{status}{COLOR_RESET}"
            else:
                status_label = f"{COLOR_GREEN}{status}{COLOR_RESET}"
                
        print(f"  • {action_type.capitalize():10} : [{status_label}] - {desc}")
        
    print("-" * 50)
    
    if args.output:
        out_filename = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_filename = f"sentinelsoc_report_{timestamp}.md"
        
    try:
        with open(out_filename, "w", encoding="utf-8") as f:
            f.write(report_markdown)
        success_msg = f"Full response playbook saved to: {os.path.abspath(out_filename)}"
        if use_color:
            print(f"{COLOR_GREEN}{success_msg}{COLOR_RESET}")
        else:
            print(success_msg)
    except Exception as e:
        print(f"{COLOR_RED if use_color else ''}[Warning] Failed to write report file: {e}{COLOR_RESET if use_color else ''}", file=sys.stderr)
        
    if trace_metrics:
        print_observability_summary(trace_metrics, use_color)
        
    run_analyst_shell(report_markdown, trace_metrics, actions, use_color)

if __name__ == "__main__":
    main()
