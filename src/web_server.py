import os
import sys
import json
import asyncio
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

# Load secure environment configuration
load_dotenv()

# Ensure root directory is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import agents
from src.main import add_windows_firewall_rule, add_hosts_sinkhole

app = FastAPI(title="SentinelSOC Web Console")

# In-memory mitigation action statuses
MITIGATION_ACTIONS = {
    "firewall": {"status": "INACTIVE", "desc": "No recommendations yet"},
    "quarantine": {"status": "INACTIVE", "desc": "No recommendations yet"},
    "dns": {"status": "INACTIVE", "desc": "No recommendations yet"}
}

# Keep a record of blocked IPs and Domains
BLOCKED_IPS = set()
BLOCKED_DOMAINS = set()

# Configuration: whether to modify local system files or simulate
LOCAL_SYSTEM_MODE = False

class AnalyzeRequest(BaseModel):
    text: str

class BlockRequest(BaseModel):
    type: str  # "ip" or "domain"
    value: str

class AskRequest(BaseModel):
    question: str
    history: List[Dict[str, str]]
    context: str

# Serve the static HTML frontend
@app.get("/")
async def read_index():
    static_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_file):
        return FileResponse(static_file)
    return {"detail": "Index file not found. Ensure frontend HTML is placed at src/static/index.html"}

@app.api_route("/api/analyze", methods=["POST"])
async def analyze_incident(req: AnalyzeRequest):
    async def event_generator():
        loop = asyncio.get_event_loop()
        try:
            # Create the generator
            gen = agents.analyze_incident_stream(req.text)
            
            def get_next(g):
                try:
                    return next(g)
                except StopIteration:
                    return None
            
            while True:
                step_str = await loop.run_in_executor(None, get_next, gen)
                if step_str is None:
                    break
                
                step_data = json.loads(step_str)
                if step_data.get("event") == "complete":
                    global MITIGATION_ACTIONS
                    actions = step_data.get("actions", {})
                    for key, val in actions.items():
                        MITIGATION_ACTIONS[key] = {
                            "status": "RECOMMENDED",
                            "desc": val.get("desc", "")
                        }
                yield {
                    "event": "message",
                    "data": step_str
                }
                # Yield control briefly to ensure responsiveness
                await asyncio.sleep(0.01)
        except Exception as e:
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)})
            }

    return EventSourceResponse(event_generator())

@app.post("/api/block")
async def execute_block(req: BlockRequest):
    global MITIGATION_ACTIONS
    val = req.value.strip()
    if req.type == "ip":
        if LOCAL_SYSTEM_MODE:
            success = add_windows_firewall_rule(val)
            if not success:
                raise HTTPException(status_code=500, detail="Failed to add Windows Firewall rule. Make sure you run as Administrator.")
            status_str = "BLOCKED"
            desc_str = f"IP rule BLOCKED at local system firewall for IP: {val}"
        else:
            # Simulate Palo Alto block
            status_str = "DEPLOYED"
            desc_str = f"Deny rule pushed to perimeter security base for IP: {val}"
        
        BLOCKED_IPS.add(val)
        MITIGATION_ACTIONS["firewall"] = {"status": status_str, "desc": desc_str}
        return {"status": "success", "action": "firewall", "data": MITIGATION_ACTIONS["firewall"]}

    elif req.type == "domain":
        if LOCAL_SYSTEM_MODE:
            success = add_hosts_sinkhole(val)
            if not success:
                raise HTTPException(status_code=500, detail="Failed to write to system hosts file. Administrator privileges needed.")
            status_str = "SINKHOLED"
            desc_str = f"DNS requests SINKHOLED in hosts file for domain: {val}"
        else:
            # Simulate DNS sinkhole
            status_str = "DEPLOYED"
            desc_str = f"DNS RPZ Sinkhole active for domain: {val}"
            
        BLOCKED_DOMAINS.add(val)
        MITIGATION_ACTIONS["dns"] = {"status": status_str, "desc": desc_str}
        return {"status": "success", "action": "dns", "data": MITIGATION_ACTIONS["dns"]}

    else:
        raise HTTPException(status_code=400, detail="Invalid block type. Must be 'ip' or 'domain'.")

@app.post("/api/ask")
async def liaison_ask(req: AskRequest):
    loop = asyncio.get_event_loop()
    try:
        # Run liaison chat query in thread pool
        def query_liaison():
            return agents.chat_follow_up(req.question, req.history, req.context)
        
        response = await loop.run_in_executor(None, query_liaison)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
async def get_status():
    return {
        "actions": MITIGATION_ACTIONS,
        "blocked_ips": list(BLOCKED_IPS),
        "blocked_domains": list(BLOCKED_DOMAINS),
        "local_system_mode": LOCAL_SYSTEM_MODE
    }

@app.get("/api/config")
async def get_config():
    key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or ""
    is_set = bool(key) and not key.startswith("your_actual") and len(key) > 10
    return {
        "api_key_configured": is_set
    }

# Check if run directly
if __name__ == "__main__":
    import uvicorn
    import argparse
    
    parser = argparse.ArgumentParser(description="SentinelSOC Web Console Application")
    parser.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"), help="Host address to bind to")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", 8000)), help="Port to run the server on")
    parser.add_argument("--local-system", action="store_true", help="Opt-in to modify local Windows Firewall and hosts file")
    
    args = parser.parse_args()
    
    LOCAL_SYSTEM_MODE = args.local_system
    
    # Mount static files folder if it exists
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
        
    print(f"[*] Starting SentinelSOC Web Server on http://{args.host}:{args.port}")
    if LOCAL_SYSTEM_MODE:
        print("[!] WARNING: Running in Local System modification mode (requires Administrator privileges).")
    else:
        print("[*] Running in Simulated Enterprise perimeter mode (safe, no Admin privileges needed).")
        
    uvicorn.run(app, host=args.host, port=args.port)
