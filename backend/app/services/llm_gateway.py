import subprocess
import logging
import time
from typing import Dict, Any, List

from app.services.model_router import model_router
from app.services.load_balancer import load_balancer

logger = logging.getLogger(__name__)

class LLMGatewayService:
    """Service to handle interactions with the local LLM (Ollama) or external APIs"""
    
    def __init__(self):
        self.default_timeout = 30
        
    def generate_response(self, prompt: str, model: str = "llama3.1:latest", temperature: float = 0.7) -> Dict[str, Any]:
        """Generate response via local ollama instance"""
        start_time = time.time()
        latency = 0.0
        
        # 1. Simulate Model Routing
        resolved_model = model_router.select_model(task_type="general")
        # 2. Simulate Load Balancing
        assigned_node = load_balancer.get_next_healthy_node()
        
        try:
            # We are using subprocess to stream/call ollama run directly for simplicity
            logger.info(f"📤 LLMGateway: Routing to {resolved_model} on node [{assigned_node}]: {prompt[:100]}...")
            
            result = subprocess.run(
                ["ollama", "run", resolved_model, prompt],
                capture_output=True,
                text=True,
                timeout=self.default_timeout
            )
            
            latency = time.time() - start_time
            
            if result.returncode != 0:
                logger.error(f"❌ LLMGateway error: {result.stderr}")
                return {
                    "success": False,
                    "response": f"Ollama error: {result.stderr}",
                    "latency": latency
                }
            
            response_text = result.stdout.strip()
            logger.info(f"📥 LLMGateway: Received response ({len(response_text)} chars) in {latency:.2f}s")
            
            return {
                "success": True,
                "response": response_text,
                "latency": latency
            }
            
        except subprocess.TimeoutExpired:
            latency = time.time() - start_time
            logger.error(f"⏱️ LLMGateway: Request timed out after {self.default_timeout}s")
            return {
                "success": False,
                "response": "Request timed out",
                "latency": latency
            }
        except Exception as e:
            latency = time.time() - start_time
            logger.error(f"❌ LLMGateway exception: {str(e)}")
            return {
                "success": False,
                "response": f"Error: {str(e)}",
                "latency": latency
            }

llm_gateway = LLMGatewayService()
