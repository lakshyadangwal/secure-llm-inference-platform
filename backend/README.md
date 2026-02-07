# Neuro-Sentry Backend

FastAPI backend with auto-detection of Ollama models and comprehensive logging.

## Features

- ✅ Auto-detects available Ollama models (priority: llama3-gpu > llama3 > mistral)
- ✅ Comprehensive logging to `backend/logs/`
- ✅ Real-time LLM integration
- ✅ Security threat detection
- ✅ Statistics tracking

## Quick Start

From the `backend` directory:

```bash
# Setup (first time only)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Logs

All logs are saved to `backend/logs/backend_TIMESTAMP.log`

Check logs in real-time:
```bash
tail -f backend/logs/backend_*.log
```

## Model Detection

The backend automatically detects and uses the best available Ollama model:
1. llama3-gpu (if available) - GPU accelerated
2. llama3 (fallback)
3. mistral (if llama3 not available)
4. First available model

Check which model is being used in the logs or at `GET /health`

## API Endpoints

- `GET /` - Service info
- `GET /health` - Health check
- `POST /chat` - Direct LLM chat
- `POST /api/prompt` - Security analysis
- `GET /api/stats` - Statistics
- `GET /api/logs` - Recent logs
