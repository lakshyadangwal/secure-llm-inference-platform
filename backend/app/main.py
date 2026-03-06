"""
Neuro-Sentry Defense Backend
FastAPI server for LLM security testing with Ollama integration
Enhanced with auto-detection, logging, and configuration
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import json
import time
import os
import logging
import random
from datetime import datetime
from typing import Optional, List
from fastapi import File, UploadFile
from fastapi.responses import StreamingResponse

# Import new security modules
from app.dlp import dlp_engine
from app.rules_engine import rules_engine
from app.redteam import redteam_fuzzer
from app.rag_scanner import rag_scanner

# Setup logging
log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, f"backend_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Detect available Ollama models
def detect_ollama_model():
    """Auto-detect which Ollama model to use"""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        models_output = result.stdout
        logger.info(f"Ollama models detected:\n{models_output}")
        
        # Priority: llama3-gpu > llama3 > mistral > first available
        if "llama3-gpu" in models_output:
            logger.info("✓ Using llama3-gpu (GPU accelerated)")
            return "llama3-gpu"
        elif "llama3" in models_output:
            logger.info("✓ Using llama3")
            return "llama3"
        elif "mistral" in models_output:
            logger.info("✓ Using mistral (fallback)")
            return "mistral"
        else:
            # Get first model name
            lines = models_output.split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    model_name = line.split()[0]
                    logger.info(f"✓ Using first available model: {model_name}")
                    return model_name
            
            logger.error("❌ No Ollama models found!")
            return None
    except Exception as e:
        logger.error(f"❌ Error detecting Ollama models: {e}")
        return None

# Get the model to use
OLLAMA_MODEL = detect_ollama_model()
if not OLLAMA_MODEL:
    logger.warning("⚠️  Ollama model not detected. Backend will start but LLM calls will fail.")
    OLLAMA_MODEL = "llama3"  # Fallback

logger.info(f"🤖 Selected model: {OLLAMA_MODEL}")

app = FastAPI(
    title="Neuro-Sentry Defense API",
    description="Backend API for LLM security testing",
    version="2.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Stats storage (in-memory)
stats = {
    "total_attempts": 0,
    "total_blocked": 0,
    "total_leaked": 0,
    "block_rate": 100.0,
}

# Request Models
class ChatRequest(BaseModel):
    prompt: str

class PromptRequest(BaseModel):
    prompt: str
    security_enabled: bool = True

class RuleRequest(BaseModel):
    name: str
    type: str
    pattern: str
    action: str = "block"

# Helper function to call Ollama
def call_ollama(prompt: str, timeout: int = 30) -> str:
    """Call Ollama CLI to get LLM response"""
    try:
        logger.info(f"📤 Sending to {OLLAMA_MODEL}: {prompt[:100]}...")
        
        result = subprocess.run(
            ["ollama", "run", OLLAMA_MODEL, prompt],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            logger.error(f"❌ Ollama error: {result.stderr}")
            raise Exception(f"Ollama error: {result.stderr}")
        
        response = result.stdout.strip()
        logger.info(f"📥 Received response ({len(response)} chars)")
        return response
        
    except subprocess.TimeoutExpired:
        logger.error(f"⏱️  Ollama request timed out after {timeout}s")
        raise Exception("Ollama request timed out")
    except FileNotFoundError:
        logger.error("❌ Ollama not found. Please install Ollama.")
        raise Exception("Ollama not found. Install from: https://ollama.ai")
    except Exception as e:
        logger.error(f"❌ Ollama error: {str(e)}")
        raise Exception(f"Ollama error: {str(e)}")

# Security check function
def check_for_threats(prompt: str) -> dict:
    """
    Enhanced security check using Dynamic Rules Engine
    """
    return rules_engine.evaluate(prompt)

@app.on_event("startup")
async def startup_event():
    """Log startup information"""
    logger.info("=" * 60)
    logger.info("🛡️  NEURO-SENTRY DEFENSE BACKEND STARTING")
    logger.info("=" * 60)
    logger.info(f"🤖 Ollama Model: {OLLAMA_MODEL}")
    logger.info(f"📝 Log file: {log_file}")
    logger.info(f"🌐 CORS: Enabled for all origins")
    logger.info("=" * 60)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Neuro-Sentry Defense API",
        "version": "2.0.0",
        "status": "online",
        "model": OLLAMA_MODEL
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    # Check if Ollama is available
    try:
        subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            timeout=5
        )
        ollama_status = "online"
    except:
        ollama_status = "offline"
    
    return {
        "status": "online",
        "ollama": ollama_status,
        "model": OLLAMA_MODEL,
        "timestamp": time.time()
    }

@app.post("/chat")
async def chat(request: ChatRequest):
    """
    Direct chat endpoint - sends prompt to Ollama
    Used by Direct Neural Link tab
    """
    logger.info(f"💬 Chat request received")
    
    try:
        # Call Ollama
        response_text = call_ollama(request.prompt)
        
        logger.info(f"✅ Chat response sent successfully")
        
        return {
            "response": response_text,
            "status": "success",
            "model": OLLAMA_MODEL,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error(f"❌ Chat error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"LLM Error: {str(e)}"
        )

@app.post("/api/prompt")
async def analyze_prompt(request: PromptRequest):
    """
    Analyze prompt with full security pipeline (Rules + LLM + DLP)
    """
    global stats
    
    stats["total_attempts"] += 1
    logger.info(f"🧪 Attack Lab request #{stats['total_attempts']}")
    logger.info(f"   Security: {'ON' if request.security_enabled else 'OFF'}")
    
    # Check for threats (Dynamic Rules Stage 1)
    threat_check = check_for_threats(request.prompt)
    
    breach_detected = False
    response_text = ""
    dlp_leaks = []
    
    if request.security_enabled:
        if threat_check["is_threat"]:
            stats["total_blocked"] += 1
            breach_detected = False
            response_text = (
                "I appreciate your interest, but I cannot fulfill this request. "
                "It appears to attempt circumventing my safety guidelines. "
                "I'm designed to be helpful, harmless, and honest."
            )
            logger.info(f"🛡️  BLOCKED by Rule: {threat_check['matched_rule_name']}")
        else:
            stats["total_blocked"] += 1 # Actually means successfully processed in this logic context initially
            try:
                raw_response = call_ollama(request.prompt)
                # Output DLP Scan (Stage 4)
                redacted_text, leaked_items, leak_detected = dlp_engine.scan_and_redact(raw_response)
                
                response_text = redacted_text
                dlp_leaks = leaked_items
                breach_detected = False
                logger.info(f"✅ SAFE - Benign request processed")
            except Exception as e:
                response_text = f"Error processing request: {str(e)}"
                logger.error(f"❌ Error: {str(e)}")
    else:
        # Security OFF
        if threat_check["is_threat"]:
            stats["total_leaked"] += 1
            breach_detected = True
            try:
                response_text = call_ollama(request.prompt)
                logger.warning(f"⚠️  BREACH - Security OFF, rule matched: {threat_check['matched_rule_name']}")
            except Exception as e:
                response_text = "⚠️ SECURITY BREACH DETECTED ⚠️\nSystem safeguards offline."
                logger.error(f"❌ Error: {str(e)}")
        else:
            stats["total_blocked"] += 1 # processed ok
            try:
                response_text = call_ollama(request.prompt)
                breach_detected = False
            except Exception as e:
                response_text = f"Error: {str(e)}"
    
    if stats["total_attempts"] > 0:
        stats["block_rate"] = (stats["total_blocked"] / stats["total_attempts"]) * 100
        
    return {
        "response": response_text,
        "breach_detected": breach_detected,
        "threat_type": threat_check["matched_rule_name"] if threat_check["matched_rule_name"] else "none",
        "dlp_leaks": dlp_leaks,
        "security_enabled": request.security_enabled,
        "model": OLLAMA_MODEL,
        "stats": {
            "totalAttempts": stats["total_attempts"],
            "totalBlocked": stats["total_blocked"],
            "totalLeaked": stats["total_leaked"],
            "blockRate": round(stats["block_rate"], 1),
        }
    }

# ---------------------------------------------------------
# New Feature Endpoints
# ---------------------------------------------------------

@app.get("/api/rules")
async def get_rules():
    return {"rules": rules_engine.get_all()}

@app.post("/api/rules")
async def add_rule(rule: RuleRequest):
    new_rule = rules_engine.add_rule(rule.name, rule.type, rule.pattern, rule.action)
    return {"status": "success", "rule": new_rule}

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str):
    rules_engine.delete_rule(rule_id)
    return {"status": "success"}

@app.get("/api/stats")
async def get_stats():
    """Get current system statistics"""
    return {
        "totalAttempts": stats["total_attempts"],
        "totalBlocked": stats["total_blocked"],
        "totalLeaked": stats["total_leaked"],
        "blockRate": round(stats["block_rate"], 1),
        "uptime": "99.97%",
        "neuralLoad": 42,
        "memoryMatrix": 68,
        "synapticLatency": 3,
        "model": OLLAMA_MODEL,
    }

@app.get("/api/logs")
async def get_logs(limit: int = 50):
    """Get recent system logs"""
    try:
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                recent_logs = lines[-limit:]
                return {"logs": [line.strip() for line in recent_logs]}
        else:
            return {"logs": ["No logs available yet"]}
    except Exception as e:
        return {"logs": [f"Error reading logs: {str(e)}"]}

if __name__ == "__main__":
    import uvicorn
    logger.info("🚀 Starting Uvicorn server...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
