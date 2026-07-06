import os
import re
import json
import time
import sys
import logging
from typing import Generator, Dict, Any, List, Optional
from dotenv import load_dotenv

# Load secure environment configuration
load_dotenv()

# Silence ADK/genai internal log spam on stderr
for _noisy_logger in (
    "google.adk", "google.genai", "google.adk.models",
    "google.adk.runners", "google.adk.flows",
    "google.adk.workflow", "google.adk.agents",
    "httpx", "httpcore",
):
    logging.getLogger(_noisy_logger).setLevel(logging.CRITICAL)

# google.adk imports
from google.adk import Agent, Runner
from google.adk.sessions import InMemorySessionService
from google import genai
from google.genai import types

# Import config and utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL, _VALID_TLDS, _LEGIT_DOMAINS
from src.utils.security import normalize_obfuscations, refang_indicator
from src import mcp_server  # local MCP tool functions

# ─────────────────────────────────────────────────────────────────────────────
# 0. Environment Setup
# ─────────────────────────────────────────────────────────────────────────────
API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
if API_KEY:
    os.environ["GOOGLE_API_KEY"] = API_KEY

# ─────────────────────────────────────────────────────────────────────────────
# 1. MCP Tool Wrappers exposed to ADK agents as @tool functions
# ─────────────────────────────────────────────────────────────────────────────

def get_ip_reputation(ip: str) -> str:
    """
    Query the threat intelligence database for the reputation of an IP address.
    Args:
        ip: The IPv4 address to investigate.
    Returns:
        A JSON string with keys: status, type, blocklists, country, isp.
    """
    return mcp_server.get_ip_reputation(ip)


def get_domain_reputation(domain: str) -> str:
    """
    Query the threat intelligence database for the reputation of a domain name.
    Args:
        domain: The domain (e.g. "badsite.com") to investigate.
    Returns:
        A JSON string with keys: status, age_days, registrar, flagged, category.
    """
    return mcp_server.get_domain_reputation(domain)


def sandbox_analyze_url(url: str) -> str:
    """
    Run a sandboxed inspection of a URL to detect phishing forms and brand impersonation.
    Args:
        url: The full URL to scan.
    Returns:
        A JSON string with keys: status, contains_forms, password_fields, brand_impersonation,
        phishing_probability, security_score.
    """
    return mcp_server.sandbox_analyze_url(url)

# ─────────────────────────────────────────────────────────────────────────────
# 2. Dynamic Agent Definitions (Supervisor-Worker Pattern)
# ─────────────────────────────────────────────────────────────────────────────

# Supervisor Agent: Directs forensics worker, triages, and calculates response playbooks
commander_agent = Agent(
    name="commander_agent",
    model=MODEL,
    instruction=(
        "You are the Lead Incident Commander at SentinelSOC. Your role is to coordinate and supervise "
        "the triage of potential security incidents. You delegate forensic investigations to the "
        "forensics_agent, review technical findings, determine threat severity (CRITICAL, SUSPICIOUS, or LOW), "
        "and compile response configs. Output response details in structured JSON when requested."
    ),
    description="Incident commander supervising SOC investigations.",
)

# Technical Worker Agent: Executes scans, queries threat feeds, and sandboxes URLs using tools
forensics_agent = Agent(
    name="forensics_agent",
    model=MODEL,
    instruction=(
        "You are the Technical Forensics Specialist at SentinelSOC. Under the Commander's direction, "
        "you extract Indicators of Compromise (IPs, domains, URLs) and check their safety.\n"
        "You MUST call get_ip_reputation for IPs, get_domain_reputation for domains, and sandbox_analyze_url "
        "for URLs. Analyze and summarize threat levels for all extracted indicators."
    ),
    description="Technical analyst worker equipped with threat feeds and URL sandboxing tools.",
    tools=[get_ip_reputation, get_domain_reputation, sandbox_analyze_url],
)

# Report Generation & Liaison Agent
report_agent = Agent(
    name="mitigation_agent",
    model=MODEL,
    instruction=(
        "You are an incident mitigation reporter. Generate a professional, beautifully formatted "
        "Incident Response Playbook in GitHub Markdown containing Executive Summary, Fraud Assessment, "
        "IOC tables, Threat Intel details, URL Sandbox metrics, Containment rules, and Audit log."
    ),
    description="Drafts response playbooks and answers follow-up inquiries.",
)

# ─────────────────────────────────────────────────────────────────────────────
# 3. ADK Sync Agent Runner Helper
# ─────────────────────────────────────────────────────────────────────────────

def _run_agent(agent: Agent, prompt: str, user_id: str = "soc_analyst", retries: int = 3) -> str:
    """
    Runs a single google.adk Agent synchronously with the Gemini API and returns
    the final text response. Each call is a fresh in-memory session.
    Retries automatically on 429 rate-limit or 5xx server errors with backoff.
    """
    if not API_KEY:
        sys.stderr.write("\n" + "="*70 + "\n")
        sys.stderr.write("[CRITICAL ERROR] Gemini API Key is missing!\n")
        sys.stderr.write("Please set GEMINI_API_KEY in your .env file.\n")
        sys.stderr.write("="*70 + "\n\n")
        raise RuntimeError("No Gemini API key configured. Set GEMINI_API_KEY in .env.")

    delay = 2.0
    last_error: Optional[Exception] = None

    for attempt in range(retries):
        try:
            session_service = InMemorySessionService()
            runner = Runner(
                app_name=agent.name,
                agent=agent,
                session_service=session_service,
            )
            session = session_service.create_session_sync(
                app_name=agent.name,
                user_id=user_id,
            )
            message = types.Content(
                role="user",
                parts=[types.Part(text=prompt)]
            )
            final_text = ""
            for event in runner.run(
                user_id=session.user_id,
                session_id=session.id,
                new_message=message,
            ):
                if event.is_final_response() and event.content and event.content.parts:
                    final_text = "".join(
                        p.text for p in event.content.parts
                        if p.text and not getattr(p, "thought", False)
                    )
            res = final_text.strip()
            if not res:
                raise RuntimeError("ADK runner failed to return any text response (empty final response)")
            return res

        except Exception as e:
            err_str = str(e)
            err_str_lower = err_str.lower()
            
            # If the ADK event loop is closed or broken, fall back to direct genai.Client call
            if "event loop is closed" in err_str_lower or "loop" in err_str_lower or "runner" in err_str_lower:
                sys.stderr.write("[ADK Event Loop Failure] Falling back to direct genai.Client API...\n")
                try:
                    client = genai.Client()
                    # If this agent has tools, we can pass them, but for chat follow-up / report they aren't needed.
                    response = client.models.generate_content(
                        model=MODEL,
                        contents=prompt,
                    )
                    if response.text:
                        return response.text.strip()
                except Exception as direct_e:
                    sys.stderr.write(f"[Direct Client Fallback Failed] {direct_e}\n")

            is_api_key_error = (
                "api_key_invalid" in err_str_lower
                or "api key not valid" in err_str_lower
                or "invalid api key" in err_str_lower
                or "api key expired" in err_str_lower
                or "key expired" in err_str_lower
                or "forbidden" in err_str_lower
                or "unauthorized" in err_str_lower
                or "invalid_argument" in err_str_lower
            )
            if is_api_key_error:
                sys.stderr.write("\n" + "="*70 + "\n")
                sys.stderr.write("[CRITICAL ERROR] Gemini API Key is invalid or has expired!\n")
                sys.stderr.write("Please update the GEMINI_API_KEY value in your .env file.\n")
                sys.stderr.write("="*70 + "\n\n")
                raise RuntimeError("Invalid or expired Gemini API key. Check your .env file.")

            is_transient = (
                "429" in err_str
                or "RESOURCE_EXHAUSTED" in err_str
                or "ResourceExhausted" in err_str
                or "_ResourceExhaustedError" in type(e).__name__
                or "quota" in err_str.lower()
                or "503" in err_str
                or "UNAVAILABLE" in err_str
                or "500" in err_str
                or "502" in err_str
            )
            if is_transient and attempt < retries - 1:
                if "429" in err_str or "quota" in err_str.lower() or "RESOURCE_EXHAUSTED" in err_str:
                    hint_match = re.search(r'retry in (\d+(?:\.\d+)?)s', err_str, re.IGNORECASE)
                    if hint_match:
                        delay = float(hint_match.group(1)) + 1.0
                    else:
                        delay = 5.0 * (attempt + 1)
                else:
                    delay = 2.0 * (attempt + 1)
                sys.stderr.write(
                    f"[Transient Error] Agent '{agent.name}' hit error: {err_str[:100]}. "
                    f"Retrying in {delay:.1f}s (attempt {attempt + 1}/{retries})...\n"
                )
                time.sleep(delay)
                last_error = e
            else:
                raise

    raise last_error  # type: ignore


import concurrent.futures

def _run_agent_with_timeout(agent: Agent, prompt: str, user_id: str = "soc_analyst", retries: int = 3, timeout: float = 12.0) -> str:
    """Runs the ADK agent inside a thread pool with an enforced execution timeout."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_run_agent, agent, prompt, user_id, retries)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise RuntimeError(f"Agent '{agent.name}' timed out after {timeout}s")


def _parse_json_from_text(text: str) -> dict:
    """Robustly extract a JSON object from an LLM text response."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise

# ─────────────────────────────────────────────────────────────────────────────
# 4. Main Multi-Agent Streaming Pipeline (Preserves contract logging names)
# ─────────────────────────────────────────────────────────────────────────────

def _estimate_cost(prompt: str, response: str) -> float:
    """Estimates the Gemini API query cost based on character-to-token ratio approximation."""
    # 1 token ≈ 4 characters
    input_tokens = len(prompt) / 4.0
    output_tokens = len(response) / 4.0
    # Gemini 2.5 Flash pricing: input $0.075 / 1M, output $0.30 / 1M
    return (input_tokens * 0.075 / 1_000_000) + (output_tokens * 0.30 / 1_000_000)


def analyze_incident_stream(incident_text: str) -> Generator[str, None, None]:
    """
    Orchestrates the collaborative Commander-Worker forensics investigation.
    Yields log events mapped to compliance logging names for benchmark suite integration.
    """
    yield json.dumps({"event": "start", "message": "Initializing SentinelSOC Multi-Agent system..."})

    trace_metrics: Dict[str, Dict[str, Any]] = {
        agent: {"duration": 0.0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
        for agent in [
            "fraud_moderator_agent", "extraction_agent",
            "threat_intel_agent", "sandbox_agent", "mitigation_agent"
        ]
    }
    use_offline = False

    # Normalize unicode homoglyphs & strip zero-width spaces
    incident_norm, has_zw, has_homoglyphs = normalize_obfuscations(incident_text)
    obfuscation_flags = []
    if has_zw:
        obfuscation_flags.append("Zero-width spaces detected and stripped from email body.")
        yield json.dumps({"event": "agent_log", "agent": "fraud_moderator_agent",
                          "message": "⚠️ Zero-width spaces detected and stripped."})
    if has_homoglyphs:
        obfuscation_flags.append("Cyrillic homoglyph characters normalized to Latin equivalents.")
        yield json.dumps({"event": "agent_log", "agent": "fraud_moderator_agent",
                          "message": "⚠️ Cyrillic homoglyph characters normalized."})

    incident_refanged = refang_indicator(incident_norm)

    # ── STAGE 0: Fraud Triage (Commander supervisor) ────────────────────────
    yield json.dumps({"event": "agent_start", "agent": "fraud_moderator_agent",
                      "message": "Evaluating email against fraud detection criteria via Gemini API..."})

    t0 = time.time()
    fraud_result = {"is_suspicious": False, "confidence_score": 0.0, "threat_type": "None", "red_flags": []}

    try:
        if use_offline:
            raise RuntimeError("Forced offline mode active")
        # Commander performs triage and initial classification
        fraud_prompt = (
            "You are the Lead Incident Commander. Triage this security incident email and perform "
            "fraud classification. Output a raw JSON with keys: is_suspicious (bool), confidence_score (float), "
            "threat_type (Phishing, BEC, Spam, Malware, or None), and red_flags (list of strings).\n\n"
            f"Email Body:\n{incident_refanged}"
        )
        raw = _run_agent_with_timeout(commander_agent, fraud_prompt)
        fraud_result = _parse_json_from_text(raw)
        trace_metrics["fraud_moderator_agent"]["cost"] = _estimate_cost(fraud_prompt, raw)
    except Exception as e:
        use_offline = True
        yield json.dumps({"event": "agent_log", "agent": "fraud_moderator_agent",
                          "message": f"Gemini API unavailable ({type(e).__name__}). Running offline keyword analysis..."})
        fraud_result = _keyword_fraud_fallback(incident_refanged)
        yield json.dumps({"event": "agent_log", "agent": "fraud_moderator_agent",
                          "message": f"[Offline] Keyword analysis complete: suspicious={fraud_result['is_suspicious']}, type={fraud_result['threat_type']}"})

    # Merge obfuscation flags
    if obfuscation_flags:
        for flag in obfuscation_flags:
            if flag not in fraud_result.setdefault("red_flags", []):
                fraud_result["red_flags"].append(flag)
        # Only escalate to suspicious if the classifier already triaged it as suspicious.
        # We preserve the classifier's clean verdict otherwise to prevent false positives.
        if fraud_result.get("is_suspicious"):
            fraud_result["confidence_score"] = max(fraud_result.get("confidence_score", 0.0), 0.95)
            if not fraud_result.get("threat_type") or fraud_result["threat_type"] == "None":
                fraud_result["threat_type"] = "Phishing"

    trace_metrics["fraud_moderator_agent"]["duration"] = time.time() - t0

    yield json.dumps({
        "event": "agent_log", "agent": "fraud_moderator_agent",
        "message": (
            f"Suspicious: {str(fraud_result.get('is_suspicious')).upper()} | "
            f"Confidence: {fraud_result.get('confidence_score', 0.0) * 100:.1f}% | "
            f"Type: {fraud_result.get('threat_type')}"
        )
    })
    for flag in fraud_result.get("red_flags", []):
        yield json.dumps({"event": "agent_log", "agent": "fraud_moderator_agent",
                          "message": f"-> Red Flag: {flag}"})

    yield json.dumps({"event": "agent_complete", "agent": "fraud_moderator_agent",
                      "message": "Content moderation assessment complete."})

    # ── STAGE 1: IOC Extraction (Commander delegates to Forensics Worker) ─────
    yield json.dumps({"event": "agent_start", "agent": "extraction_agent",
                      "message": "Scanning incident data for Indicators of Compromise (IOCs)..."})

    t1 = time.time()
    iocs = {"ips": [], "domains": [], "urls": []}

    try:
        if use_offline:
            raise RuntimeError("Forced offline mode active")
        extract_prompt = (
            "You are the Forensics Specialist. Extract all raw Indicators of Compromise from this incident text.\n"
            "Do NOT extract clean system domains or email local-parts.\n"
            "Return ONLY a raw JSON object with keys: ips (list), domains (list), urls (list).\n\n"
            f"Text:\n{incident_refanged}"
        )
        raw = _run_agent_with_timeout(forensics_agent, extract_prompt)
        iocs = _parse_json_from_text(raw)
        trace_metrics["extraction_agent"]["cost"] = _estimate_cost(extract_prompt, raw)
    except Exception as e:
        use_offline = True
        yield json.dumps({"event": "agent_log", "agent": "extraction_agent",
                          "message": f"IOC extraction error: {e}. Falling back to regex parser."})
        iocs = _regex_fallback_extract(incident_refanged)

    trace_metrics["extraction_agent"]["duration"] = time.time() - t1

    yield json.dumps({"event": "agent_log", "agent": "extraction_agent",
                      "message": f"Extracted IOCs: {len(iocs.get('ips', []))} IPs, "
                                 f"{len(iocs.get('domains', []))} domains, "
                                 f"{len(iocs.get('urls', []))} URLs."})
    for ip in iocs.get("ips", []):
        yield json.dumps({"event": "agent_log", "agent": "extraction_agent",
                          "message": f"-> Identified IP address: {ip}"})
    for domain in iocs.get("domains", []):
        yield json.dumps({"event": "agent_log", "agent": "extraction_agent",
                          "message": f"-> Identified Domain: {domain}"})
    for url in iocs.get("urls", []):
        yield json.dumps({"event": "agent_log", "agent": "extraction_agent",
                          "message": f"-> Identified URL: {url}"})

    yield json.dumps({"event": "agent_complete", "agent": "extraction_agent",
                      "message": "IOC Extraction complete."})

    # ── STAGE 2: Threat Intel Reputation (Worker calls MCP tools) ─────────────
    has_iocs = bool(iocs.get("ips") or iocs.get("domains"))
    yield json.dumps({"event": "agent_start", "agent": "threat_intel_agent",
                      "message": "Connecting to SentinelThreatIntel MCP Server to query reputation..."})

    t2 = time.time()
    ip_reports: Dict[str, Any] = {}
    domain_reports: Dict[str, Any] = {}

    if has_iocs:
        try:
            if use_offline:
                raise RuntimeError("Forced offline mode active")
            intel_prompt = (
                "You are the Forensics Specialist. Lookup reputation for these IOCs using tools.\n"
                f"IOCs: {json.dumps(iocs)}\n\n"
                "Query get_ip_reputation for IPs and get_domain_reputation for domains.\n"
                "Return a raw JSON with keys 'ip_reports' and 'domain_reports'."
            )
            raw = _run_agent_with_timeout(forensics_agent, intel_prompt)
            parsed = _parse_json_from_text(raw)
            ip_reports = parsed.get("ip_reports", {})
            domain_reports = parsed.get("domain_reports", {})
            trace_metrics["threat_intel_agent"]["cost"] = _estimate_cost(intel_prompt, raw)
        except Exception as e:
            use_offline = True
            yield json.dumps({"event": "agent_log", "agent": "threat_intel_agent",
                              "message": f"Threat intel error: {e}. Falling back to direct MCP calls."})
            for ip in iocs.get("ips", []):
                try:
                    ip_reports[ip] = json.loads(mcp_server.get_ip_reputation(ip))
                except Exception:
                    ip_reports[ip] = {"status": "unknown", "type": "unknown", "country": "?", "isp": "?", "blocklists": 0}
            for domain in iocs.get("domains", []):
                try:
                    domain_reports[domain] = json.loads(mcp_server.get_domain_reputation(domain))
                except Exception:
                    domain_reports[domain] = {"status": "unknown", "age_days": 0, "registrar": "?", "flagged": False, "category": "unknown"}

    trace_metrics["threat_intel_agent"]["duration"] = time.time() - t2

    for ip, rep in ip_reports.items():
        status = rep.get("status", "unknown")
        icon = "🔴" if status == "malicious" else ("🟡" if status == "suspicious" else "🟢")
        yield json.dumps({"event": "agent_log", "agent": "threat_intel_agent",
                          "message": f"MCP Response: {icon} IP {ip} is {status.upper()} ({rep.get('type', '?')}) in {rep.get('country', '?')} via {rep.get('isp', '?')}."})
    for domain, rep in domain_reports.items():
        status = rep.get("status", "unknown")
        icon = "🔴" if status == "malicious" else ("🟡" if "suspicious" in status.lower() else "🟢")
        yield json.dumps({"event": "agent_log", "agent": "threat_intel_agent",
                          "message": f"MCP Response: {icon} Domain {domain} is {status.upper()} (Age: {rep.get('age_days', '?')} days, Registrar: {rep.get('registrar', '?')})."})

    if not has_iocs:
        yield json.dumps({"event": "agent_log", "agent": "threat_intel_agent",
                          "message": "No IPs or domains found. Skipping threat intel lookup."})

    yield json.dumps({"event": "agent_complete", "agent": "threat_intel_agent",
                      "message": "Threat Intelligence validation complete."})

    # ── STAGE 3: URL Sandboxing (Worker queries sandboxing tool) ──────────────
    has_urls = bool(iocs.get("urls"))
    yield json.dumps({"event": "agent_start", "agent": "sandbox_agent",
                      "message": "Initializing isolated sandbox scanning environment..."})

    t3 = time.time()
    url_reports: Dict[str, Any] = {}

    if has_urls:
        try:
            if use_offline:
                raise RuntimeError("Forced offline mode active")
            sandbox_prompt = (
                "You are the Forensics Specialist. Analyze these URLs in the sandbox using sandbox_analyze_url.\n"
                f"URLs: {json.dumps(iocs.get('urls'))}\n\n"
                "Return a raw JSON with key 'url_reports' containing results for all URLs."
            )
            raw = _run_agent_with_timeout(forensics_agent, sandbox_prompt)
            parsed = _parse_json_from_text(raw)
            url_reports = parsed.get("url_reports", {})
            trace_metrics["sandbox_agent"]["cost"] = _estimate_cost(sandbox_prompt, raw)
        except Exception as e:
            use_offline = True
            yield json.dumps({"event": "agent_log", "agent": "sandbox_agent",
                              "message": f"Sandbox agent error: {e}. Falling back to direct MCP calls."})
            for url in iocs.get("urls", []):
                try:
                    url_reports[url] = json.loads(mcp_server.sandbox_analyze_url(url))
                except Exception:
                    url_reports[url] = {"status": "unknown", "contains_forms": False, "password_fields": 0,
                                        "brand_impersonation": "unknown", "phishing_probability": 0.0, "security_score": 100}

    trace_metrics["sandbox_agent"]["duration"] = time.time() - t3

    for url, scan in url_reports.items():
        phish_pct = scan.get("phishing_probability", 0.0) * 100
        yield json.dumps({"event": "agent_log", "agent": "sandbox_agent",
                          "message": (
                              f"Sandbox Report for {url}: Forms={scan.get('contains_forms', False)}, "
                              f"Password Fields={scan.get('password_fields', 0)}, "
                              f"Impersonating={scan.get('brand_impersonation', 'unknown')}, "
                              f"Phish Probability={phish_pct:.1f}%"
                          )})

    if not has_urls:
        yield json.dumps({"event": "agent_log", "agent": "sandbox_agent",
                          "message": "No URLs found. Skipping sandbox analysis."})

    yield json.dumps({"event": "agent_complete", "agent": "sandbox_agent",
                      "message": "Safe URL sandboxing analysis finished."})

    # ── STAGE 4: Mitigation & Containment Playbook (Commander compiles IR) ────
    yield json.dumps({"event": "agent_start", "agent": "mitigation_agent",
                      "message": "Analyzing multi-stage logs to compute response actions..."})

    t4 = time.time()

    # Calculate severity based on technical forensic telemetry
    max_phish_prob = max((r.get("phishing_probability", 0.0) for r in url_reports.values()), default=0.0)
    has_malicious_ip = any(r.get("status") == "malicious" for r in ip_reports.values())
    has_malicious_domain = any(r.get("status") == "malicious" for r in domain_reports.values())
    is_suspicious = fraud_result.get("is_suspicious", False)
    confidence = fraud_result.get("confidence_score", 0.0)

    if max_phish_prob > 0.8 or has_malicious_ip or has_malicious_domain or (is_suspicious and confidence > 0.9):
        severity = "CRITICAL"
    elif max_phish_prob > 0.4 or any("suspicious" in r.get("status", "").lower() for r in {**ip_reports, **domain_reports}.values()) or is_suspicious:
        severity = "SUSPICIOUS"
    else:
        severity = "LOW"

    # Formulate containment configurations
    malicious_ips = [ip for ip, r in ip_reports.items() if r.get("status") == "malicious"]
    malicious_domains = [d for d, r in domain_reports.items() if r.get("status") == "malicious"]

    if severity == "CRITICAL":
        action_fw = f"BLOCK inbound/outbound connection rules for IP(s): {', '.join(malicious_ips)}" if malicious_ips else "Block outbound connections to malicious hosts on local subnet"
        action_mbox = "QUARANTINE mailbox. Revoke user session keys. Enable MFA re-auth."
        action_dns = f"SINKHOLE DNS lookup requests for domain(s): {', '.join(malicious_domains)}" if malicious_domains else "SINKHOLE resolved domain addresses via local hostfile"
        fw_status, mbox_status, dns_status = "BLOCKED", "QUARANTINED", "SINKHOLED"
    elif severity == "SUSPICIOUS":
        action_fw = "Monitor connections to suspicious network IPs"
        action_mbox = "Flag inbox with external warning banners"
        action_dns = "Watch domain lookup patterns in core resolvers"
        fw_status, mbox_status, dns_status = "MONITOR", "ALERTED", "WATCHED"
    else:
        action_fw = "No firewall action required"
        action_mbox = "No mailbox action required"
        action_dns = "No DNS action required"
        fw_status, mbox_status, dns_status = "INACTIVE", "INACTIVE", "INACTIVE"

    yield json.dumps({"event": "agent_log", "agent": "mitigation_agent",
                      "message": f"Threat severity calculated: {severity}."})
    yield json.dumps({"event": "agent_log", "agent": "mitigation_agent",
                      "message": "Drafting Markdown Incident Response Report via Gemini API..."})

    analysis_summary = {
        "severity": severity,
        "fraud_assessment": fraud_result,
        "iocs": iocs,
        "ip_reports": ip_reports,
        "domain_reports": domain_reports,
        "url_reports": url_reports,
        "proposed_actions": {
            "firewall": action_fw,
            "mailbox": action_mbox,
            "dns": action_dns,
        }
    }

    report_markdown = ""
    try:
        if use_offline:
            raise RuntimeError("Forced offline mode active")
        report_prompt = (
            "Generate a professional Incident Response Report based on this forensics data:\n\n"
            f"{json.dumps(analysis_summary, indent=2)}\n\n"
            "Use markdown tables, alerts, and sections: Executive Summary, Forensic Analysis, Containment Playbook, and Audit Log."
        )
        report_markdown = _run_agent_with_timeout(report_agent, report_prompt)
        trace_metrics["mitigation_agent"]["cost"] = _estimate_cost(report_prompt, report_markdown)
    except Exception as e:
        use_offline = True
        yield json.dumps({"event": "agent_log", "agent": "mitigation_agent",
                          "message": f"Report generation error: {e}. Using fallback template."})
        report_markdown = _build_fallback_report(severity, fraud_result, iocs, ip_reports, domain_reports, url_reports, action_fw, action_mbox, action_dns)

    trace_metrics["mitigation_agent"]["duration"] = time.time() - t4

    yield json.dumps({"event": "agent_complete", "agent": "mitigation_agent",
                      "message": "Incident mitigation playbook completed."})

    yield json.dumps({
        "event": "complete",
        "severity": severity,
        "actions": {
            "firewall": {"status": fw_status, "desc": action_fw},
            "quarantine": {"status": mbox_status, "desc": action_mbox},
            "dns": {"status": dns_status, "desc": action_dns},
        },
        "report": report_markdown,
        "fraud_assessment": fraud_result,
        "trace_metrics": trace_metrics,
        "message": "Incident mitigation report generated. Security loops finalized."
    })

# ─────────────────────────────────────────────────────────────────────────────
# 5. Multi-turn Liaison Chat Follow-up
# ─────────────────────────────────────────────────────────────────────────────

def chat_follow_up(question: str, history: List[Dict[str, str]], context: str) -> Dict[str, Any]:
    """Answers analyst follow-up questions using the report/liaison agent."""
    if not API_KEY:
        return {
            "text": "No Gemini API key configured. Please set GEMINI_API_KEY in your .env file.",
            "metrics": {"duration": 0.0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
        }

    start_time = time.time()
    history_text = "\n".join(
        f"{'Analyst' if m['role'] == 'user' else 'Liaison'}: {m['text']}"
        for m in history
    )
    prompt = (
        f"INCIDENT CONTEXT:\n{context}\n\n"
        f"CONVERSATION HISTORY:\n{history_text}\n\n"
        f"Analyst question: {question}\nLead Incident Liaison response:"
    )
    try:
        response_text = _run_agent(report_agent, prompt)
        return {
            "text": response_text,
            "metrics": {
                "duration": time.time() - start_time,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost": 0.0,
            }
        }
    except Exception as e:
        # Local offline fallback QA assistant
        q_lower = question.lower()
        if "why" in q_lower or "reason" in q_lower:
            reply = "Based on local security rules, this incident was flagged due to high-risk patterns (e.g. advance fee UPI payment request, document harvesting, or suspicious links). We recommend deploying firewall/DNS containment immediately."
        elif "block" in q_lower or "firewall" in q_lower or "dns" in q_lower:
            reply = "Containment block rules can be deployed directly from the Mitigation Room by clicking the buttons. Firewall rule blocks the target IP; DNS sinkhole redirects queries to 127.0.0.1."
        else:
            reply = "Liaison Offline Assistant: Gemini API is currently unavailable. Please review the Forensic playbook in the right panel or click to deploy recommended containment blocks."

        return {
            "text": reply,
            "metrics": {"duration": time.time() - start_time, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
        }

# ─────────────────────────────────────────────────────────────────────────────
# 6. Fallback Rule Engines
# ─────────────────────────────────────────────────────────────────────────────

def _keyword_fraud_fallback(text: str) -> Dict[str, Any]:
    """Offline rule-based fraud detector."""
    t = text.lower()
    red_flags: List[str] = []
    scores: Dict[str, float] = {"Phishing": 0.0, "BEC": 0.0, "Spam": 0.0, "Malware": 0.0}

    if any(w in t for w in ["within 24 hours", "within 48 hours", "act immediately",
                             "urgent action", "final notice", "expires today",
                             "last chance", "do it now", "immediately"]):
        red_flags.append("Urgency / time-pressure language detected")
        scores["Phishing"] += 0.25
        scores["BEC"] += 0.15

    if any(w in t for w in ["verify your identity", "confirm your credentials",
                             "click here to verify", "update your password",
                             "enter your otp", "login to confirm", "verify account",
                             "account suspended", "account limited", "account restricted"]):
        red_flags.append("Credential harvesting language detected")
        scores["Phishing"] += 0.40

    if any(w in t for w in ["wire transfer", "bank transfer", "swift transfer",
                             "transfer the amount", "process the payment",
                             "pay now", "payment required", "send money"]):
        red_flags.append("Financial wire transfer / payment request detected")
        scores["BEC"] += 0.45

    if any(w in t for w in ["security deposit", "registration fee", "processing fee",
                             "refundable deposit", "small fee", "pay to confirm",
                             "block your seat", "seat confirmation fee",
                             "aadhaar", "pan card", "upload your documents"]):
        red_flags.append("Advance fee / job scam pattern: payment or document demand before joining")
        scores["Phishing"] += 0.50

    if any(w in t for w in ["ceo", "chief executive", "managing director",
                             "board meeting", "do not call", "keep this confidential",
                             "don't discuss", "strictly confidential"]):
        red_flags.append("Authority impersonation / BEC secrecy demand")
        scores["BEC"] += 0.50

    sender_match = re.search(r'from:(.*?)(?:<([^>]+)>|$)', t)
    subject_match = re.search(r'subject:(.*)', t)
    
    display_name = sender_match.group(1) if sender_match else ""
    sender_email = sender_match.group(2) if sender_match and sender_match.group(2) else (sender_match.group(1) if sender_match else "")
    subject_text = subject_match.group(1) if subject_match else ""
    
    brand_context = (display_name + " " + subject_text).lower()
    
    if sender_email:
        brand_spoofs = {
            "paypal": "paypal.com", "amazon": "amazon.com", "google": "google.com",
            "microsoft": "microsoft.com", "apple": "apple.com", "wipro": "wipro.com",
            "infosys": "infosys.com", "tcs": "tcs.com", "dhl": "dhl.com",
            "fedex": "fedex.com", "netflix": "netflix.com", "hdfc": "hdfcbank.com",
        }
        for brand, real_domain in brand_spoofs.items():
            if brand in brand_context and real_domain not in sender_email:
                red_flags.append(f"Brand impersonation: claims to be {brand.title()} but sender domain is not {real_domain}")
                scores["Phishing"] += 0.60
                break

    if any(w in t for w in ["selected for internship", "you have been selected",
                             "offer letter", "joining date", "stipend",
                             "campus recruitment", "hr executive", "congratulations"]):
        if any(w in t for w in ["deposit", "fee", "payment", "upi", "paytm",
                                  "upload", "aadhaar", "pan card", "document"]):
            red_flags.append("Fake job/internship offer with advance payment or document phishing")
            scores["Phishing"] += 0.55

    if any(w in t for w in [".exe", ".zip attachment", "download and run",
                             "enable macros", "click to enable content",
                             "open the attachment", "invoice attached"]):
        red_flags.append("Malware delivery lure detected")
        scores["Malware"] += 0.60

    if any(w in t for w in ["you have won", "lottery", "claim your prize",
                             "free iphone", "congratulations you are selected",
                             "million dollars", "inheritance", "nigerian prince"]):
        red_flags.append("Classic spam / lottery scam pattern")
        scores["Spam"] += 0.70

    if not red_flags:
        return {
            "is_suspicious": False, "confidence_score": 0.05,
            "threat_type": "None", "red_flags": [],
        }

    best_type = max(scores, key=lambda k: scores[k])
    best_score = scores[best_type]
    confidence = min(0.92, max(0.55, best_score))

    return {
        "is_suspicious": True,
        "confidence_score": round(confidence, 2),
        "threat_type": best_type,
        "red_flags": red_flags,
    }


def _regex_fallback_extract(text: str) -> Dict[str, List[str]]:
    """Fallback IOC extractor using regex."""
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    url_pattern = r'https?://[^\s<>"\' \t]+'

    ips = list(set(re.findall(ip_pattern, text)))
    urls = list(set(re.findall(url_pattern, text)))

    # Strip email addresses
    text_for_domains = re.sub(r'[a-zA-Z0-9._%+\-]+@', '@', text)

    # Collect domains
    raw_domains = re.findall(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        text_for_domains
    )

    seen = set()
    domains = []
    for d in raw_domains:
        d_lower = d.lower()
        tld = d_lower.rsplit(".", 1)[-1]
        if tld not in _VALID_TLDS:
            continue
        if re.match(ip_pattern, d):
            continue
        parts = d_lower.split(".")
        if len(parts) < 2:
            continue
        if len(parts) == 2 and all(p.isalpha() for p in parts) and tld in {"hr", "recruitment", "singh", "sharma"}:
            continue
        if d_lower in _LEGIT_DOMAINS:
            continue
        if d_lower in seen:
            continue
        seen.add(d_lower)
        domains.append(d_lower)

    return {"ips": ips, "domains": domains, "urls": urls}


def _build_fallback_report(severity, fraud_result, iocs, ip_reports, domain_reports, url_reports, action_fw, action_mbox, action_dns) -> str:
    """Build a standard fallback report when the mitigation agent fails."""
    lines = [
        f"# SentinelSOC Incident Response Report",
        f"**Threat Level**: {severity}",
        f"**Generated on**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        f"SentinelSOC has assessed the submitted incident and assigned a severity of **{severity}**.",
        "",
        "## 2. Fraud & Threat Assessment",
        f"- **Is Suspicious**: {str(fraud_result.get('is_suspicious')).upper()}",
        f"- **Confidence**: {fraud_result.get('confidence_score', 0.0) * 100:.1f}%",
        f"- **Threat Type**: {fraud_result.get('threat_type', 'None')}",
        "",
        "### Red Flags:",
    ]
    for f in fraud_result.get("red_flags", []) or ["None identified."]:
        lines.append(f"- {f}")

    lines += ["", "## 3. Indicators of Compromise", ""]
    lines.append("| Type | Indicator | Status | Details |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for ip, r in ip_reports.items():
        lines.append(f"| IP | `{ip}` | **{r.get('status', '?').upper()}** | {r.get('type', '?')} ({r.get('country', '?')}) |")
    for d, r in domain_reports.items():
        lines.append(f"| Domain | `{d}` | **{r.get('status', '?').upper()}** | Age: {r.get('age_days', '?')} days |")
    for u, r in url_reports.items():
        lines.append(f"| URL | `{u}` | Phishing {r.get('phishing_probability', 0)*100:.0f}% | Forms: {r.get('contains_forms', False)}, Impersonating: {r.get('brand_impersonation', '?')} |")

    lines += [
        "",
        "## 4. Mitigation & Containment Playbook",
        "",
        "> [!WARNING]",
        "> Critical safeguards have been mapped based on threat telemetry.",
        "",
        f"- **Firewall**: `{action_fw}`",
        f"- **Mailbox**: `{action_mbox}`",
        f"- **DNS**: `{action_dns}`",
    ]
    return "\n".join(lines)
