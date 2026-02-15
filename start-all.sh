#!/bin/bash

# Neuro-Sentry Defense System - Complete Launcher
# Auto-detects everything, handles setup, and launches all services

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BACKEND_DIR="$SCRIPT_DIR/backend"

# PID storage
OLLAMA_PID=""
BACKEND_PID=""

# Network detection
detect_network_ip() {
    # Try to get local network IP
    if command -v ip &> /dev/null; then
        # Linux
        ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[^ ]+' || echo ""
    elif command -v ifconfig &> /dev/null; then
        # macOS/BSD
        ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -n1 || echo ""
    else
        echo ""
    fi
}

NETWORK_IP=$(detect_network_ip)

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗              ║${NC}"
echo -e "${CYAN}║   ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔════╝              ║${NC}"
echo -e "${CYAN}║   ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║                   ║${NC}"
echo -e "${CYAN}║   ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║                   ║${NC}"
echo -e "${CYAN}║   ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╗              ║${NC}"
echo -e "${CYAN}║   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝              ║${NC}"
echo -e "${CYAN}║                                                            ║${NC}"
echo -e "${CYAN}║        N E U R O  •  S E N T R Y                           ║${NC}"
echo -e "${CYAN}║   LLM Threat Detection | Runtime Integrity | Zero Trust    ║${NC}"
echo -e "${CYAN}║              v2.0.0  —  NETWORK MODE ONLINE                ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""


# =====================================================
# CHECK REQUIREMENTS
# =====================================================

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}[ PRE-FLIGHT ]  Verifying System Integrity & Dependencies${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""


# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js not found${NC}"
    echo -e "${YELLOW}   Install from: https://nodejs.org/${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Node.js: $(node --version)"

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}❌ npm not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} npm: $(npm --version)"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 not found${NC}"
    echo -e "${YELLOW}   Install Python 3.8+${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python: $(python3 --version)"

# Check Ollama
if ! command -v ollama &> /dev/null; then
    echo -e "${RED}❌ Ollama not found${NC}"
    echo -e "${YELLOW}   Install from: https://ollama.ai${NC}"
    echo -e "${YELLOW}   Quick install: curl https://ollama.ai/install.sh | sh${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Ollama: found"

# Detect Ollama models
echo ""
echo -e "${CYAN}🤖 Detecting Ollama models...${NC}"
OLLAMA_MODELS=$(ollama list 2>/dev/null || echo "")

if echo "$OLLAMA_MODELS" | grep -q "llama3-gpu"; then
    SELECTED_MODEL="llama3-gpu"
    echo -e "${GREEN}✓${NC} Found: ${MAGENTA}llama3-gpu${NC} ${GREEN}(GPU accelerated)${NC} ⚡"
elif echo "$OLLAMA_MODELS" | grep -q "llama3"; then
    SELECTED_MODEL="llama3"
    echo -e "${GREEN}✓${NC} Found: ${MAGENTA}llama3${NC}"
else
    echo -e "${YELLOW}⚠️  llama3 not found${NC}"
    echo ""
    echo -e "${CYAN}Available models:${NC}"
    echo "$OLLAMA_MODELS"
    echo ""
    echo -e "${YELLOW}Downloading llama3 model (this may take a few minutes)...${NC}"
    ollama pull llama3
    SELECTED_MODEL="llama3"
    echo -e "${GREEN}✓${NC} Downloaded: llama3"
fi

echo -e "${CYAN}   Selected model:${NC} ${MAGENTA}${SELECTED_MODEL}${NC}"

echo ""

# =====================================================
# FRONTEND SETUP
# =====================================================

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}[ FRONTEND ]  Initializing Interface Layer${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""


cd "$SCRIPT_DIR"

# Install frontend dependencies
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}📦 Installing frontend dependencies...${NC}"
    npm install --silent
    echo -e "${GREEN}✓${NC} Frontend dependencies installed"
else
    echo -e "${GREEN}✓${NC} Frontend dependencies already installed"
fi

# Check if qrcode is installed
if ! grep -q '"qrcode"' package.json 2>/dev/null; then
    echo -e "${YELLOW}📦 Installing qrcode package for network access...${NC}"
    npm install qrcode --save
    echo -e "${GREEN}✓${NC} QR code package installed"
fi

# Create .env if needed
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚙️  Creating .env configuration...${NC}"
    cat > .env << EOF
# API Configuration - set to 'auto' for smart network detection
VITE_API_URL=auto
VITE_APP_NAME=Neuro-Sentry Defense
VITE_APP_VERSION=2.0.0
EOF
    echo -e "${GREEN}✓${NC} Configuration created"
else
    echo -e "${GREEN}✓${NC} Configuration exists"
fi

echo ""

# =====================================================
# BACKEND SETUP
# =====================================================

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}[ BACKEND ]  Initializing Core Services${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""


if [ -d "$BACKEND_DIR" ]; then
    cd "$BACKEND_DIR"
    
    # Create venv if needed
    if [ ! -d "venv" ]; then
        echo -e "${YELLOW}📦 Creating Python virtual environment...${NC}"
        python3 -m venv venv
        echo -e "${GREEN}✓${NC} Virtual environment created"
    else
        echo -e "${GREEN}✓${NC} Virtual environment exists"
    fi
    
    # Activate venv
    source venv/bin/activate
    
    # Install backend dependencies
    if [ -f "requirements.txt" ]; then
        echo -e "${YELLOW}📦 Installing backend dependencies (this may take a minute)...${NC}"
        pip install --upgrade pip > /dev/null 2>&1
        pip install -r requirements.txt
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓${NC} Backend dependencies installed"
        else
            echo -e "${RED}❌ Failed to install backend dependencies${NC}"
            echo -e "${YELLOW}   Try manually: cd backend && source venv/bin/activate && pip install -r requirements.txt${NC}"
            exit 1
        fi
    fi
    
    # Create logs directory
    mkdir -p logs
    echo -e "${GREEN}✓${NC} Logs directory ready"
    
    cd "$SCRIPT_DIR"
else
    echo -e "${RED}❌ Backend directory not found at: $BACKEND_DIR${NC}"
    exit 1
fi

echo ""

# =====================================================
# LAUNCH SERVICES
# =====================================================

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}[ EXECUTION ]  Bringing Services Online${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Start Ollama if not running
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${YELLOW}🤖 Starting Ollama service...${NC}"
    ollama serve > /dev/null 2>&1 &
    OLLAMA_PID=$!
    sleep 2
    echo -e "${GREEN}✓${NC} Ollama running (PID: $OLLAMA_PID)"
else
    echo -e "${GREEN}✓${NC} Ollama already running"
fi

# Start Backend
echo -e "${YELLOW}⚡ Starting FastAPI backend...${NC}"
cd "$BACKEND_DIR"
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 > /dev/null 2>&1 &
BACKEND_PID=$!
cd "$SCRIPT_DIR"

# Wait for backend to start
sleep 3

# Check if backend started successfully
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Backend running (PID: $BACKEND_PID)"
    echo -e "${CYAN}   API:${NC} http://localhost:8000"
    echo -e "${CYAN}   Logs:${NC} backend/logs/"
else
    echo -e "${RED}❌ Backend failed to start${NC}"
    echo -e "${YELLOW}   Check logs in: backend/logs/${NC}"
fi

echo ""

# =====================================================
# NETWORK ACCESS
# =====================================================

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}[ ACCESS ]  Network & Connectivity${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${GREEN}✓ Local Access (This Computer):${NC}"
echo -e "  ${WHITE}Frontend:${NC} ${CYAN}http://localhost:5173${NC}"
echo -e "  ${WHITE}Backend:${NC}  ${CYAN}http://localhost:8000${NC}"
echo ""

if [ ! -z "$NETWORK_IP" ]; then
    echo -e "${GREEN}✓ Network Access (Other Devices):${NC}"
    echo -e "  ${WHITE}Frontend:${NC} ${MAGENTA}http://${NETWORK_IP}:5173${NC}"
    echo -e "  ${WHITE}Backend:${NC}  ${MAGENTA}http://${NETWORK_IP}:8000${NC}"
    echo ""
    echo -e "${YELLOW}📱 Mobile Access:${NC}"
    echo -e "  1. Connect phone to the ${WHITE}same WiFi network${NC}"
    echo -e "  2. Go to: ${MAGENTA}http://${NETWORK_IP}:5173${NC}"
    echo -e "  3. Or click the ${CYAN}Network button${NC} in the app to scan QR code"
else
    echo -e "${YELLOW}⚠️  Network IP could not be detected${NC}"
    echo -e "  The app will still work locally at ${CYAN}http://localhost:5173${NC}"
fi

echo ""

# =====================================================
# STATUS & CLEANUP
# =====================================================

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}[ STATUS ]  Live Service Telemetry${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}✓ Ollama:${NC}"
echo -e "  ${CYAN}Model:${NC} ${MAGENTA}${SELECTED_MODEL}${NC}"
echo -e "  ${CYAN}Port:${NC} 11434"
echo ""
echo -e "${GREEN}✓ Backend:${NC}"
echo -e "  ${CYAN}API:${NC} http://localhost:8000"
if [ ! -z "$NETWORK_IP" ]; then
    echo -e "  ${CYAN}Network:${NC} http://${NETWORK_IP}:8000"
fi
echo -e "  ${CYAN}Logs:${NC} backend/logs/"
echo ""
echo -e "${GREEN}✓ Frontend:${NC}"
echo -e "  ${CYAN}Local:${NC} http://localhost:5173"
if [ ! -z "$NETWORK_IP" ]; then
    echo -e "  ${CYAN}Network:${NC} http://${NETWORK_IP}:5173"
fi
echo -e "  ${CYAN}Status:${NC} Starting..."
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Shutting down services...${NC}"
    
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Backend stopped"
    fi
    
    if [ ! -z "$OLLAMA_PID" ]; then
        kill $OLLAMA_PID 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Ollama stopped"
    fi
    
    echo ""
    echo -e "${CYAN}█████████████████████████████████████████████${NC}"
    echo -e "${CYAN}   NEURO-SENTRY DEFENSE SYSTEM — OFFLINE     ${NC}"
    echo -e "${CYAN}   ALL ACTIVE MONITORS DISENGAGED            ${NC}"
    echo -e "${CYAN}█████████████████████████████████████████████${NC}"
    echo ""

    exit 0
}

# Set trap for cleanup
trap cleanup INT TERM

# Start Frontend (this blocks)
echo -e "${YELLOW}⏳ Starting frontend...${NC}"
echo -e "${CYAN}   Press Ctrl+C to stop all services${NC}"
echo ""

cd "$SCRIPT_DIR"
npm run dev

# This only runs if npm exits
cleanup