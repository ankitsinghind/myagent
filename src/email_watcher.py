import os
import sys
import time
import argparse
import imaplib
import email
from email.header import decode_header
import json
from datetime import datetime
from dotenv import load_dotenv

# Ensure root and src folders are in the system path for local packages
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import agents

# ANSI Terminal Colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"
COLOR_GREY = "\033[90m"

def clean_header(header_value: str) -> str:
    """Decode email header values (like Subject or From)."""
    if not header_value:
        return ""
    decoded = decode_header(header_value)
    parts = []
    for val, encoding in decoded:
        if isinstance(val, bytes):
            try:
                parts.append(val.decode(encoding or "utf-8", errors="ignore"))
            except Exception:
                parts.append(val.decode("latin1", errors="ignore"))
        else:
            parts.append(str(val))
    return "".join(parts)

def extract_email_body(msg: email.message.Message) -> str:
    """Recursively extract plain text or HTML body from email MIME structure."""
    body = ""
    html_body = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
                
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    body += payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    html_body += payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            body_text = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
            if content_type == "text/html":
                html_body = body_text
            else:
                body = body_text
        except Exception:
            pass
            
    # Prefer text body, fallback to HTML body if text is empty
    final_body = body.strip() if body.strip() else html_body.strip()
    return final_body

def connect_imap() -> imaplib.IMAP4_SSL:
    """Connect to IMAP server using environment configurations."""
    load_dotenv()
    
    server = os.getenv("IMAP_SERVER")
    port = int(os.getenv("IMAP_PORT", "993"))
    user = os.getenv("IMAP_EMAIL")
    password = os.getenv("IMAP_PASSWORD")
    
    if not server or not user or not password:
        raise ValueError(
            "Missing IMAP configurations in environment. "
            "Please check that IMAP_SERVER, IMAP_EMAIL, and IMAP_PASSWORD are configured in your .env file."
        )
        
    print(f"[*] Connecting to IMAP server {server}:{port}...")
    mail = imaplib.IMAP4_SSL(server, port)
    print(f"[*] Logging in as {user}...")
    mail.login(user, password)
    return mail

def process_email(email_id: bytes, mail: imaplib.IMAP4_SSL, mark_read: bool) -> bool:
    """Fetch, parse, and scan an email using the multi-agent pipeline."""
    # Fetch email content
    # RFC822 fetches the whole message. If mark_read is False, we use PEEK to prevent automatic marking as read
    fetch_cmd = "(RFC822.PEEK)" if not mark_read else "(RFC822)"
    res, data = mail.fetch(email_id, fetch_cmd)
    if res != "OK" or not data or not data[0]:
        print(f"{COLOR_RED}[Error] Failed to fetch email ID {email_id.decode()}{COLOR_RESET}")
        return False
        
    raw_email = data[0][1]
    msg = email.message_from_bytes(raw_email)
    
    subject = clean_header(msg.get("Subject"))
    sender = clean_header(msg.get("From"))
    date_str = clean_header(msg.get("Date"))
    body = extract_email_body(msg)
    
    print("\n" + "="*60)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Ingested Email ID: {email_id.decode()}{COLOR_RESET}")
    print(f"{COLOR_BOLD}From   :{COLOR_RESET} {sender}")
    print(f"{COLOR_BOLD}Subject:{COLOR_RESET} {subject}")
    print(f"{COLOR_BOLD}Date   :{COLOR_RESET} {date_str}")
    print("="*60)
    
    if not body:
        print(f"{COLOR_YELLOW}[Warning] Email body is empty. Scanning headers/subject only.{COLOR_RESET}")
        scan_payload = f"Subject: {subject}\nFrom: {sender}\nDate: {date_str}"
    else:
        scan_payload = f"Subject: {subject}\nFrom: {sender}\nDate: {date_str}\n\n{body}"
        
    print(f"[*] Starting multi-agent security scan...")
    
    report_markdown = ""
    severity = "LOW"
    actions = {}
    
    try:
        for step_str in agents.analyze_incident_stream(scan_payload):
            step = json.loads(step_str)
            event = step.get("event")
            
            if event == "start":
                print(f"  [*] {step.get('message')}")
            elif event == "agent_start":
                print(f"  🤖 [Agent: {step.get('agent')}] {step.get('message')}")
            elif event == "agent_log":
                msg_log = step.get("message")
                print(f"    • {msg_log}")
            elif event == "agent_complete":
                print(f"  ✓ [Agent: {step.get('agent')}] {step.get('message')}")
            elif event == "complete":
                severity = step.get("severity", "LOW")
                actions = step.get("actions", {})
                report_markdown = step.get("report", "")
                
        print(f"\n[*] Scan Complete. Calculated Threat Severity: {COLOR_BOLD}{COLOR_RED if severity == 'CRITICAL' else COLOR_YELLOW if severity == 'SUSPICIOUS' else COLOR_GREEN}{severity}{COLOR_RESET}")
        
        # Ensure reports/ directory exists
        os.makedirs("reports", exist_ok=True)
        safe_subject = "".join(c for c in subject if c.isalnum() or c in (" ", "-", "_")).rstrip()
        safe_subject = safe_subject[:50].replace(" ", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join("reports", f"report_{timestamp}_{safe_subject}.md")
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_markdown)
            
        print(f"{COLOR_GREEN}✓ Security Playbook saved to: {os.path.abspath(report_path)}{COLOR_RESET}\n")
        return True
        
    except Exception as e:
        print(f"{COLOR_RED}[Fatal Error] Failed to run security pipeline: {e}{COLOR_RESET}")
        return False

def check_inbox(mail: imaplib.IMAP4_SSL, folder: str, limit: int, mark_read: bool) -> int:
    """Connect to folder, find unread emails, and trigger analysis."""
    print(f"[*] Selecting folder: '{folder}'...")
    res, data = mail.select(folder)
    if res != "OK":
        print(f"{COLOR_RED}[Error] Failed to select folder '{folder}': {data}{COLOR_RESET}")
        return 0
        
    print("[*] Searching for unseen (unread) messages...")
    res, data = mail.search(None, "UNSEEN")
    if res != "OK" or not data:
        print("[*] No unseen messages found.")
        return 0
        
    email_ids = data[0].split()
    # IMAP returns IDs in ascending order (oldest first). Reverse to process newest first.
    email_ids = list(reversed(email_ids))
    total_unseen = len(email_ids)
    if total_unseen == 0:
        print("[*] Inbox is clean. No unseen emails.")
        return 0
        
    print(f"[*] Found {total_unseen} unseen email(s).")
    
    # Process up to the configured limit
    processed_count = 0
    for email_id in email_ids[:limit]:
        success = process_email(email_id, mail, mark_read)
        if success:
            processed_count += 1
            
    return processed_count

def main():
    parser = argparse.ArgumentParser(
        description="SentinelSOC Automated & Manual IMAP Email Security Watcher."
    )
    parser.add_argument(
        "--watch", "-w",
        action="store_true",
        help="Run in continuous watch mode (polling loop)."
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=15,
        help="Polling interval in seconds when in watch mode (default: 15s)."
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=1,
        help="Maximum number of unseen emails to process per check (default: 1)."
    )
    parser.add_argument(
        "--no-mark-read",
        action="store_true",
        help="Do not mark emails as read after scanning (leaves them unseen)."
    )
    
    args = parser.parse_args()
    
    mark_read = not args.no_mark_read
    load_dotenv()
    folder = os.getenv("IMAP_FOLDER", "INBOX")
    
    try:
        mail = connect_imap()
    except Exception as e:
        print(f"{COLOR_RED}[Error] Connection failed: {e}{COLOR_RESET}")
        sys.exit(1)
        
    try:
        if args.watch:
            print(f"\n[*] Starting Continuous Watch Mode (polling every {args.interval}s). Press Ctrl+C to stop.")
            while True:
                try:
                    check_inbox(mail, folder, args.limit, mark_read)
                except (imaplib.IMAP4.abort, imaplib.IMAP4.readonly) as e:
                    # Reconnect on connection loss
                    print(f"{COLOR_YELLOW}[!] Connection lost: {e}. Reconnecting...{COLOR_RESET}")
                    time.sleep(5)
                    mail = connect_imap()
                    
                time.sleep(args.interval)
        else:
            print("\n[*] Running Manual/Single-Run Scan...")
            processed = check_inbox(mail, folder, args.limit, mark_read)
            print(f"[*] Manual scan complete. Processed {processed} email(s).")
            mail.logout()
            
    except KeyboardInterrupt:
        print("\n[*] Exiting Email Watcher. Goodbye.")
        try:
            mail.logout()
        except Exception:
            pass
            
if __name__ == "__main__":
    main()
