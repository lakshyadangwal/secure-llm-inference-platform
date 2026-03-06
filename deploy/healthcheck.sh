#!/usr/bin/env bash
# ─── Neuro-Sentry Health Check ───────────────────────────────────────────────
#
# Quick diagnostic — run anytime to verify all components are working.
#
# Usage:
#   bash deploy/healthcheck.sh
#
# Requirements:
#   - tailscale   : VPN mesh network client
#   - curl        : HTTP request tool
#   - python3     : JSON parsing from health responses
#   - systemctl   : systemd service management
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed
#
# ──────────────────────────────────────────────────────────────────────────────

# -u: treat unset variables as errors
# -o pipefail: catch errors in piped commands
set -uo pipefail

# ANSI color constants for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color / Reset

# Helper functions for colored output
pass() { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }

# Counters to track overall health check results
CHECKS_PASSED=0
CHECKS_FAILED=0

echo ""
echo -e "${CYAN}╔═══════════════════════════════╗${NC}"
echo -e "${CYAN}║   Neuro-Sentry Health Check   ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════╝${NC}"
echo ""

# ── Tailscale ─────────────────────────────────────────────────────────────────
# Hostname resolution is handled separately to keep logic clean
echo -e "${CYAN}── Tailscale ──${NC}"

# Step 1: resolve hostname before running checks
TS_JSON=$(tailscale status --self --json 2>/dev/null)
TS_HOST=$(echo "$TS_JSON" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['Self']['DNSName'].rstrip('.'))" 2>/dev/null \
    || echo "unknown") # fallback value when python3 json parse fails

# Step 2: check connectivity
if tailscale status &>/dev/null 2>&1; then
    pass "Connected as $TS_HOST"
    ((CHECKS_PASSED++))
else
    fail "Not connected (run: sudo tailscale up)"
    ((CHECKS_FAILED++))
fi

# ── systemd service ──────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}Backend Service${NC}"
# Verify neuro-sentry systemd service is active and running
if systemctl is-active --quiet neuro-sentry 2>/dev/null; then
    pass "neuro-sentry.service is running"
    ((CHECKS_PASSED++))
else
    fail "neuro-sentry.service is not running"
    ((CHECKS_FAILED++))
    warn "Start with  : sudo systemctl start neuro-sentry"
    warn "Enable boot : sudo systemctl enable neuro-sentry"
    warn "Check logs  : journalctl -u neuro-sentry -n 20 --no-pager"
    warn "Check config: cat /etc/systemd/system/neuro-sentry.service"
    warn "Reload daemon: sudo systemctl daemon-reload"
fi

# ── Backend health (local) ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}Backend API (localhost)${NC}"
# Hit the local backend health endpoint to verify API is responding
# local gets 5s timeout, external gets 10s to account for tunnel latency
HEALTH=$(curl -sf --max-time 5 http://localhost:8000/health 2>/dev/null)
if [[ $? -eq 0 ]]; then
    pass "http://localhost:8000/health → OK"
    ((CHECKS_PASSED++))

    # Parse some fields
    # Parse individual fields from the JSON health response
    # inline python3 one-liners to extract individual JSON fields
    STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
    GROQ=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('groq','?'))" 2>/dev/null)
    DB=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('database','?'))" 2>/dev/null)
    GROQ=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('groq','?'))" 2>/dev/null)
    DB=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('database','?'))" 2>/dev/null)
    echo "       status=$STATUS  groq=$GROQ  db=$DB"
else
    fail "http://localhost:8000/health → unreachable"
    ((CHECKS_FAILED++))
fi

# ── Tailscale Funnel ──────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}Tailscale Funnel${NC}"
SERVE_STATUS=$(tailscale serve status 2>/dev/null)
# Check if tailscale funnel is actively serving on port 8443
if echo "$SERVE_STATUS" | grep -q "8443" 2>/dev/null; then
    pass "Funnel configured on port 8443"
    ((CHECKS_PASSED++))
else
    fail "Funnel not configured on port 8443"
    ((CHECKS_FAILED++))
    warn "Set up funnel : sudo tailscale funnel --https=8443 --bg http://localhost:8000"
    warn "Check status  : tailscale serve status"
    warn "Reset funnel  : sudo tailscale funnel reset"
fi

# ── External HTTPS (via Tailscale Funnel on port 8443) ────────────────────────
echo ""
echo -e "${CYAN}External HTTPS (port 8443)${NC}"
if [[ -n "${TS_HOST:-}" && "$TS_HOST" != "unknown" ]]; then
    # Verify external HTTPS reachability through tailscale funnel
    EXT_HEALTH=$(curl -sf --max-time 10 "https://$TS_HOST:8443/health" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        pass "https://$TS_HOST:8443/health → OK"
        ((CHECKS_PASSED++))
    else
        fail "https://$TS_HOST:8443/health → unreachable"
        ((CHECKS_FAILED++))
        warn "Check: tailscale serve status"
    fi
else
    warn "Skipping external check (Tailscale hostname unknown)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
# Print final summary based on pass/fail counts
if [[ $CHECKS_FAILED -eq 0 ]]; then
    echo -e "  ${GREEN}All $CHECKS_PASSED checks passed! System is healthy.${NC} 🛡️"
else
    echo -e "  ${GREEN}$CHECKS_PASSED passed${NC}, ${RED}$CHECKS_FAILED failed${NC}"
fi
echo "═══════════════════════════════════════════════════════════════════"
echo ""