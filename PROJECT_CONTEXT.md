# NEURO-SENTRY LLM THREAT DETECTION — COMPLETE PROJECT CONTEXT
> Feed this file to any AI for instant context about the entire project.

---

## 1. PROJECT IDENTITY

- **Name**: Neuro-Sentry Defense
- **Version**: 2.0.0
- **Purpose**: Real-time LLM security platform — a firewall for AI. Intercepts prompts before they reach the LLM, runs them through a 3-stage defense pipeline (217 regex rules across 14 categories → ML classifier → score fusion), and blocks/flags/allows based on risk scores.
- **Architecture**: React 18 frontend + FastAPI Python backend + Groq LLM API
- **Standalone Mode**: Frontend works fully without backend — demo data + localStorage fallback

---

## 2. FILE STRUCTURE

```
neuro-sentry-llm-threat-detection/
├── src/                          # Frontend (React + Vite)
│   ├── App.jsx                   # Root app — 15-tab router, console, network panel
│   ├── main.jsx                  # React DOM entry point
│   ├── api.js                    # Axios API client — 10 endpoints, smart URL resolution
│   ├── index.css                 # Global CSS — dark theme, CSS variables, Tailwind overrides
│   ├── components/               # 50 component files total
│   │   ├── Header.jsx            # Top bar: ML classifier status, Google SSO, user profile
│   │   ├── Dashboard.jsx         # Overview tab wrapper
│   │   ├── StatsGrid.jsx         # Live stats: attempts, blocked, flagged, leaked, block rate
│   │   ├── StatusCard.jsx        # Individual stat card with accent colors
│   │   ├── ConsolePanel.jsx      # Fixed bottom terminal: minimize/restore/maximize (red/yellow/green dots)
│   │   ├── NetworkPanel.jsx      # Floating network status button, dynamic positioning
│   │   ├── GoogleLogin.jsx       # Google OAuth SSO flow
│   │   ├── DefenseToggle.jsx     # ON/OFF toggle for security pipeline
│   │   ├── AttackSidebar.jsx     # Left sidebar: attack scenario list (lab + dashboard views)
│   │   ├── AttackLab.jsx         # Attack simulation with step-by-step pipeline visualization
│   │   ├── AttackFlowVisualizer.jsx  # SVG attack flow diagram with animated nodes
│   │   ├── DirectChat.jsx        # Neural Link — direct LLM chat through pipeline
│   │   ├── MonitoringPanel.jsx   # Security Ops Center — 3 tabs: threat feed, sessions, summary
│   │   ├── BatchTesting.jsx      # Batch prompt testing with CSV upload
│   │   ├── ThreatAnalytics.jsx   # Advanced threat analytics and charts
│   │   ├── ThreatMap.jsx         # Interactive global map — pan/zoom/click threats
│   │   ├── RuleBuilder.jsx       # Rule engine CRUD — regex/keyword rules with testing sandbox
│   │   ├── RedTeamFuzzer.jsx     # Automated fuzzer — 12 attack strategies, terminal feed
│   │   ├── RagScanner.jsx        # RAG context poisoning scanner — client-side chunk analysis
│   │   ├── IndexPage.jsx         # Landing/index page
│   │   ├── ToastNotification.jsx # Toast notification system (ToastProvider + useToast hook)
│   │   │
│   │   ├── analytics/            # Analytics tab components
│   │   │   ├── AnalyticsDashboard.jsx  # Summary cards + events table + usage chart
│   │   │   ├── MetricCard.jsx          # Individual metric display card
│   │   │   ├── SecurityEventsTable.jsx # Tabular security events with severity badges
│   │   │   └── UsageChart.jsx          # 24-hour bar chart with CSS-only rendering
│   │   │
│   │   ├── audit/                # Audit log components
│   │   │   ├── AuditLogs.jsx     # Main audit log viewer with filtering
│   │   │   ├── LogFilter.jsx     # Filter controls for audit logs
│   │   │   └── LogViewer.jsx     # Individual log entry renderer
│   │   │
│   │   ├── playground/           # AI Playground components
│   │   │   ├── Playground.jsx    # Playground layout — model selector + chat + system prompt
│   │   │   ├── ChatWindow.jsx    # Chat interface — backend-first, simulation fallback
│   │   │   ├── MessageBubble.jsx # Individual chat message with pipeline metadata
│   │   │   ├── ModelSelector.jsx # Groq model dropdown
│   │   │   ├── PromptCard.jsx    # Prompt template card
│   │   │   ├── PromptLibrary.jsx # Pre-built prompt templates
│   │   │   └── SystemPromptInput.jsx  # System prompt text editor
│   │   │
│   │   ├── projects/             # Workspace management
│   │   │   ├── ProjectList.jsx   # Project CRUD — localStorage, 3 demo projects
│   │   │   └── ProjectCard.jsx   # Individual project card with API key
│   │   │
│   │   ├── quotas/               # Usage quotas
│   │   │   ├── Quotas.jsx        # Quota management layout
│   │   │   └── QuotaProgress.jsx # Visual quota usage bars
│   │   │
│   │   ├── routing/              # Traffic routing
│   │   │   ├── RoutingDashboard.jsx  # Routing configuration
│   │   │   ├── NodeStatus.jsx        # Individual node health
│   │   │   └── TrafficGraph.jsx      # Traffic flow visualization
│   │   │
│   │   ├── security/             # Security-specific components
│   │   │   ├── ThreatIntelBoard.jsx  # 9 APT threat profiles (Lazarus, APT-29, Volt Typhoon, etc.)
│   │   │   ├── ThreatCard.jsx        # Individual threat detail card
│   │   │   └── PiiSettings.jsx       # DLP config — mask emails/phones/SSN/cards, localStorage
│   │   │
│   │   ├── settings/             # Settings panel
│   │   │   ├── SettingsLayout.jsx    # Settings tab layout with sub-navigation
│   │   │   ├── ApiKeysSettings.jsx   # API key CRUD — generate/delete/copy/show-hide, localStorage
│   │   │   ├── SecuritySettings.jsx  # Force PII redaction toggle, audit log level selector
│   │   │   └── ModelPreferences.jsx  # Primary model selector, semantic caching toggle
│   │   │
│   │   └── index.js              # Barrel exports for all components
│   │
│   ├── hooks/
│   │   ├── useStats.js           # Polls /api/stats every N ms, returns { stats, connected }
│   │   └── useSecurityHooks.js   # 33KB security hooks: encryption, threat detection, validation
│   │
│   ├── utils/
│   │   ├── analyticsUtils.js     # Analytics computation helpers
│   │   ├── cryptoUtils.js        # Client-side crypto: hashing, encryption, key generation
│   │   └── networkSecurity.js    # Network security utilities: CORS, CSP, rate limiting
│   │
│   ├── data/
│   │   └── attackScenarios.js    # 6+ attack scenario definitions for Attack Lab
│   │
│   ├── context/
│   │   └── ThemeContext.jsx       # Dark/light theme provider (CSS variable switching)
│   │
│   └── services/
│       └── api.js                 # Legacy API client (kept for backward compat)
│
├── backend/                       # FastAPI Python backend
│   ├── app/
│   │   ├── main.py               # FastAPI app — all route definitions
│   │   ├── pipeline.py           # 3-stage defense pipeline orchestrator
│   │   ├── rules.py              # 217 rules across 14 categories + input normalizer
│   │   ├── rules_engine.py       # Rule engine execution
│   │   ├── classifier.py         # Groq ML classifier integration
│   │   ├── inference.py          # LLM inference (Groq API)
│   │   ├── audit.py              # Audit logging — SQLite persistence
│   │   ├── adaptive.py           # Adaptive session tracking + escalation
│   │   ├── dlp.py                # Data Loss Prevention — PII detection + redaction
│   │   ├── rag_scanner.py        # RAG document scanning for injections
│   │   ├── redteam.py            # Red team fuzzing utilities
│   │   ├── batch.py              # Batch prompt processing
│   │   ├── auth.py               # API key + Google OAuth authentication
│   │   ├── config.py             # Environment variable configuration
│   │   ├── db.py                 # Database connection (SQLite / PostgreSQL)
│   │   └── requirements.txt      # Python dependencies
│   │
│   ├── scripts/
│   │   ├── train_classifier.py   # Train local DistilBERT threat classifier
│   │   ├── collect_dataset.py    # Collect training data from prompts
│   │   └── export_audit_as_training_data.py  # Export audit logs as training CSV
│   │
│   ├── tests/                    # 15+ test files covering pipeline, API, defense scenarios
│   ├── neuro_sentry.db           # SQLite database file
│   └── rules_db.json             # Persisted rule definitions
│
├── docker/                        # Docker configuration
├── deploy/                        # Deployment scripts
├── docs/                          # Documentation (11 files)
├── .env.example                   # Environment variable template
├── docker-compose.yml             # Docker Compose for full stack
├── package.json                   # NPM dependencies
├── tailwind.config.js             # Tailwind CSS configuration
├── vite.config.js                 # Vite build configuration
└── start-all.sh / start-all.bat  # One-click startup scripts
```

---

## 3. SECURITY PIPELINE (CORE ARCHITECTURE)

```
User Prompt
    │
    ▼
┌──────────────────────────────────────────┐
│  STAGE 1: RULE ENGINE (217 rules)        │
│  - Input normalizer: zero-width strip,   │
│    NFKC, base64/hex/URL decode, leet,    │
│    word-splitting, reversed text detect   │
│  - 14 categories: jailbreak, injection,  │
│    extraction, encoding, social, priv,   │
│    roleplay, manipulation, dangerous,    │
│    token_manip, context_overflow,        │
│    indirect_injection, model_extraction, │
│    multi_agent_attack                    │
│  - If score > FAST_BLOCK_THRESHOLD (85): │
│    → Immediately BLOCK (skip Stage 2+3)  │
│  - Output: rule_score (0-100)            │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  STAGE 2: ML/LLM CLASSIFIER (Groq)      │
│  - Model: llama-3.1-8b-instant           │
│  - Classification: benign / malicious    │
│  - Confidence: 0.0 to 1.0               │
│  - Optional local DistilBERT fallback    │
│  - Output: ml_label, ml_confidence       │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  STAGE 3: SCORE FUSION                   │
│  - Weighted combination:                 │
│    risk_score = α * rule_score           │
│                + β * (ml_confidence * 100)│
│  - Thresholds:                           │
│    risk ≥ BLOCK_THRESHOLD (65) → BLOCK   │
│    risk ≥ FLAG_THRESHOLD (35)  → FLAG    │
│    risk < 35                   → ALLOW   │
│  - Output: risk_score, decision,         │
│    attack_type, primary_reason           │
└──────────────┬───────────────────────────┘
               │
         ┌─────┴─────┐
         ▼           ▼
    BLOCKED         ALLOWED
    (logged)        → LLM Inference
                    → Response to user
```

---

## 4. API ENDPOINTS (src/api.js)

| Method | Endpoint | Description | Used By |
|--------|----------|-------------|---------|
| POST | `/api/prompt` | Run prompt through full security pipeline | Dashboard, AttackLab, DirectChat |
| POST | `/chat` | Direct chat (bypasses some pipeline stages) | DirectChat |
| GET | `/api/stats` | Live stats: total attempts, blocked, flagged, block rate, uptime | useStats hook → Header, StatsGrid |
| GET | `/api/audit/summary` | Aggregate: totals, attack type distribution, top rules | MonitoringPanel |
| GET | `/api/audit` | Paginated audit log with filtering | AuditLogs, MonitoringPanel |
| GET | `/api/adaptive/sessions` | Session tracking with escalation status | MonitoringPanel |
| GET | `/api/audit/export` | Export all audit data as JSON | MonitoringPanel (admin only) |
| POST | `/api/audit/import` | Import audit data from JSON | MonitoringPanel (admin only) |
| DELETE | `/api/audit/reset` | Delete all audit records | MonitoringPanel (admin only) |
| GET | `/health` | Health check: status, database, uptime | NetworkPanel |
| POST | `/api/playground/chat` | Playground chat with model/temp/system prompt | ChatWindow |

**Base URL Resolution** (api.js):
- `VITE_API_URL=auto` (default) → `localhost:8000` on dev, same origin on deployed
- `VITE_API_URL=https://...` → direct URL (Railway/Tailscale)
- Auth: `X-API-Key` header (from VITE_API_KEY) + Google OAuth Bearer token (from sessionStorage)
- Session ID: `web-{uuid}` stored in sessionStorage, sent with every prompt

---

## 5. ALL 15 UI TABS

### Tab 1: Overview (Dashboard)
- **Component**: `Dashboard.jsx` → `StatsGrid.jsx` → `StatusCard.jsx`
- **Data**: Polled from `/api/stats` every 8s via `useStats` hook
- **Shows**: Total attempts, blocked, flagged, leaked, allowed, block rate, uptime
- **Features**: Defense toggle (ON/OFF), attack sidebar, breach animation (red border shake)

### Tab 2: Analytics
- **Component**: `AnalyticsDashboard.jsx` → `MetricCard.jsx`, `SecurityEventsTable.jsx`, `UsageChart.jsx`
- **Data**: Demo — 3 metric cards, 7 security events, 24-hour usage bars
- **Standalone**: Falls back to demo data when backend offline

### Tab 3: Audit Logs
- **Component**: `AuditLogs.jsx` → `LogFilter.jsx`, `LogViewer.jsx`
- **Data**: From `/api/audit` with filtering (decision, attack type, date range)
- **Features**: Paginated, searchable, filterable

### Tab 4: Threat Intel
- **Component**: `ThreatIntelBoard.jsx` → `ThreatCard.jsx`
- **Data**: 9 hardcoded APT threats — APT-29, Lazarus, Volt Typhoon, FIN7, OilRig, Scattered Spider, DarkHydrus, Kimsuky, Sidewinder
- **Each has**: Severity (critical/high/medium), attack type, IOCs, TTPs, description

### Tab 5: DLP Setup
- **Component**: `PiiSettings.jsx`
- **Features**: Toggle masking for emails, phones, SSN, credit cards. Action: redact or block. Saves to localStorage key `ns_dlp_settings`

### Tab 6: Threat Map
- **Component**: `ThreatMap.jsx`
- **Data**: 12 geo-located attack points with actor attribution (APT-29, Lazarus, Volt Typhoon, etc.)
- **Interactivity**: Scroll-to-zoom (cursor-centered), drag-to-pan, click threats for detail panel, threat index sidebar (click to zoom-to-threat)
- **Visuals**: SVG with animated radar sweep, pulsing nodes, attack lines, continent outlines

### Tab 7: Rule Engine
- **Component**: `RuleBuilder.jsx`
- **Data**: localStorage key `ns_rules`, seeded with 5 defaults (SQLi, Jailbreak, PII, System Prompt, Base64)
- **CRUD**: Add rules (name, type: keyword/regex, pattern, action: block/flag), delete rules
- **Testing sandbox**: Paste any text → runs against all rules → shows block/pass result + matched keywords

### Tab 8: Auto Fuzzer
- **Component**: `RedTeamFuzzer.jsx`
- **Features**: 12 attack strategies — DAN Jailbreak, Roleplay Extraction, Base64 Obfuscation, Multi-turn Manipulation, Markdown Injection, Context Window Overflow, Indirect Prompt Injection, Adversarial Suffix (GCG), Refusal Suppression, Token Smuggling, Translation Bypass, Fictional Framing
- **Simulation**: setTimeout loop, ~85% block rate, terminal-style live log
- **Stats**: Total payloads, defenses bypassed, threats blocked

### Tab 9: RAG Scanner
- **Component**: `RagScanner.jsx`
- **Upload**: .txt, .md, .csv, .json files
- **Client-side analysis**: Chunks text into ~500 char pieces, runs 8 regex patterns (system prompt override, role manipulation, hidden instruction, DAN/jailbreak, data exfiltration, encoded payload, HTML injection, indirect injection)
- **Output**: DOCUMENT SECURE or DOCUMENT POISONED, chunk-level detail with matched rule names

### Tab 10: Workspaces
- **Component**: `ProjectList.jsx` → `ProjectCard.jsx`
- **Data**: localStorage key `ns_projects`, seeded with 3 projects (Production LLM, Staging Environment, Red Team Sandbox)
- **CRUD**: Create new projects with auto-generated API keys

### Tab 11: AI Playground
- **Component**: `Playground.jsx` → `ChatWindow.jsx`, `ModelSelector.jsx`, `SystemPromptInput.jsx`, `PromptLibrary.jsx`
- **Features**: Multi-model chat, temperature control, system prompt editor, security toggle
- **Backend**: Tries `/api/playground/chat` first (5s timeout) → falls back to simulation
- **Simulation**: Threat keyword detection → blocked response with pipeline stage info; safe → normal AI response

### Tab 12: Attack Lab
- **Component**: `AttackLab.jsx` → `AttackFlowVisualizer.jsx`
- **Features**: Attack scenario selector, step-by-step execution, SVG flow diagram
- **Data**: Attack scenarios from `data/attackScenarios.js`

### Tab 13: Neural Link
- **Component**: `DirectChat.jsx`
- **Features**: Minimal chat interface, sends prompts through full pipeline via `/api/prompt`

### Tab 14: Security Ops (Monitoring)
- **Component**: `MonitoringPanel.jsx`
- **3 Sub-tabs**: Threat Feed (6-column grid), Sessions (per-session risk tracking), Summary (attack distribution charts)
- **Admin-only**: Export/Import/Reset restricted to emails: admin@neurosentry.io, root@neurosentry.io
- **Demo data**: 10 audit logs + 4 sessions (2 escalated) for offline mode
- **Polling**: Every 4 seconds from backend, graceful fallback

### Tab 15: Settings
- **Component**: `SettingsLayout.jsx` → `ApiKeysSettings.jsx`, `SecuritySettings.jsx`, `ModelPreferences.jsx`
- **API Keys**: CRUD with generate/delete/copy/show-hide (localStorage key `ns_api_keys`)
- **Security**: Force PII redaction globally, audit logging level (localStorage key `ns_security_settings`)
- **Models**: Primary model (Llama 3.1/Phi-2/Mistral/DeepSeek), semantic caching (localStorage key `ns_model_prefs`)

---

## 6. LOCALSTORAGE KEYS

| Key | Component | Contents |
|-----|-----------|----------|
| `ns_rules` | RuleBuilder | Array of rule objects: {id, name, type, pattern, action} |
| `ns_projects` | ProjectList | Array of project objects: {id, name, description, apiKey, created} |
| `ns_api_keys` | ApiKeysSettings | Array of key objects: {id, name, key, created} |
| `ns_security_settings` | SecuritySettings | {forcePiiRedaction: bool, auditLevel: string} |
| `ns_model_prefs` | ModelPreferences | {primaryModel: string, semanticCaching: bool} |
| `ns_dlp_settings` | PiiSettings | {mask_emails, mask_phones, mask_ssn, mask_credit_cards, action} |
| `ns_session_id` | api.js (sessionStorage) | web-{uuid} — stable per browser tab |
| `ns_google_credential` | GoogleLogin (sessionStorage) | Google OAuth JWT token |
| `ns_google_user` | GoogleLogin (sessionStorage) | {email, name, picture} |

---

## 7. ENVIRONMENT VARIABLES

```bash
# Backend
GROQ_API_KEY=gsk_...                    # Groq API key for ML classifier + inference
INFERENCE_MODEL=llama-3.3-70b-versatile # Model for LLM responses
CLASSIFIER_MODEL=llama-3.1-8b-instant   # Model for threat classification
LOCAL_ML_MODEL_PATH=backend/models/deberta-threat-classifier  # Optional local model (DistilBERT)
DATABASE_URL=                           # PostgreSQL URL (blank = SQLite fallback)
NEURO_SENTRY_API_KEY=                   # API key for route protection (blank = no auth)
BLOCK_THRESHOLD=65                      # Risk score threshold for blocking
FLAG_THRESHOLD=35                       # Risk score threshold for flagging
FAST_BLOCK_THRESHOLD=85                 # Rule score for instant block (skip ML)

# Frontend (Vite)
VITE_API_URL=http://localhost:8000      # Backend URL (or "auto")
VITE_API_KEY=                           # API key sent as X-API-Key header
VITE_GOOGLE_CLIENT_ID=                  # Google OAuth client ID
```

---

## 8. DEPENDENCIES

### Frontend (package.json)
| Package | Version | Purpose |
|---------|---------|---------|
| react | ^18.3.1 | UI framework |
| react-dom | ^18.3.1 | DOM rendering |
| framer-motion | ^11.0.0 | Animations and transitions |
| lucide-react | ^0.263.1 | Icon library |
| axios | ^1.6.2 | HTTP client for API calls |
| @react-oauth/google | ^0.13.4 | Google SSO |
| js-cookie | ^3.0.5 | Cookie management |
| qrcode | ^1.5.3 | QR code generation |
| vite | ^5.2.11 | Build tool |
| tailwindcss | ^3.4.3 | Utility-first CSS framework |

### Backend (requirements.txt)
- FastAPI + Uvicorn — ASGI web server
- Groq SDK — Groq API client
- SQLAlchemy — ORM for audit database
- Pydantic — Data validation
- python-jose — JWT handling
- httpx — Async HTTP client

---

## 9. BACKEND MODULES

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI app with all route definitions |
| `pipeline.py` | 3-stage orchestrator: rules → classifier → fusion |
| `rules.py` + `rules_engine.py` | 217 rules across 14 categories, input normalizer, regex matching, scoring |
| `classifier.py` | Groq API integration for prompt classification |
| `inference.py` | Groq API integration for LLM response generation |
| `audit.py` | SQLite/PostgreSQL audit logging with CRUD |
| `adaptive.py` | Per-session risk tracking, escalation logic |
| `dlp.py` | PII detection (email, phone, SSN, credit card regex) |
| `rag_scanner.py` | Document chunk scanning for hidden injections |
| `redteam.py` | Red team fuzzing logic server-side |
| `batch.py` | Batch prompt processing |
| `auth.py` | API key validation + Google OAuth verification |
| `config.py` | Environment variable loading + defaults |
| `db.py` | Database connection management |

---

## 10. UTILITY MODULES

| File | Size | Purpose |
|------|------|---------|
| `hooks/useStats.js` | 3.4KB | Polls /api/stats at configurable interval, returns {stats, connected} |
| `hooks/useSecurityHooks.js` | 33KB | Comprehensive security hooks: useThreatDetection, useEncryption, useValidation, useNetworkSecurity, useAuditLog |
| `utils/analyticsUtils.js` | 27KB | Analytics computation: aggregations, time-series processing, statistical calculations |
| `utils/cryptoUtils.js` | 13KB | Client-side crypto: AES encryption/decryption, SHA hashing, HMAC, key derivation |
| `utils/networkSecurity.js` | 37KB | Network security: CSP policy generation, CORS validation, rate limiter, integrity checks |

---

## 11. AUTHENTICATION FLOW

```
1. User clicks "Sign In" → Google OAuth popup
2. Google returns JWT credential
3. Stored in sessionStorage: ns_google_credential (JWT), ns_google_user ({email, name, picture})
4. Axios interceptor auto-attaches Authorization: Bearer {jwt} to all API requests
5. Backend validates JWT in auth.py
6. Non-authenticated users see "ACCESS DENIED" overlay on all tabs except Overview
7. Admin emails (admin@neurosentry.io, root@neurosentry.io) get access to export/import/reset
```

---

## 12. UI LAYOUT

```
┌─────────────────────────────────────────────────────────────┐
│ HEADER: ML Status | Logo | User Profile | Google Login      │  ← fixed top, z-40
├──────┬──────────────────────────────────────────────────────┤
│      │  TAB BAR: 15 tabs (scrollable)                       │
│ SIDE │  [Defense Toggle row — only on lab/dashboard]        │
│ BAR  ├──────────────────────────────────────────────────────┤
│(lab/ │                                                      │
│dash  │  ACTIVE VIEW CONTENT                                 │
│only) │  (flex-1, scroll, animated transitions)              │
│      │                                                      │
├──────┴──────────────────────────────────────────────────────┤
│ CONSOLE PANEL: Terminal logs (minimize/restore/maximize)    │  ← fixed bottom, z-30
│ [NETWORK button]                                            │  ← floating, z-20
└─────────────────────────────────────────────────────────────┘

Layout sizing:
- Header: fixed, 5rem top padding
- Console states: minimized=40px, default=144px, maximized=60vh
- Main content height = 100vh - header(5rem) - console padding
- All views use absolute positioning with overflow-auto within their container
```

---

## 13. DEMO/STANDALONE DATA

When backend is offline, every component falls back to hardcoded data:

| Component | Demo Data |
|-----------|-----------|
| ThreatIntelBoard | 9 APT threats with IOCs and TTPs |
| ThreatMap | 12 geo-located attacks (Moscow, Beijing, Tehran, Pyongyang, NYC, London, Paris, Delhi, Tokyo, São Paulo, Cairo, Istanbul) |
| AnalyticsDashboard | Summary metrics + 7 security events |
| UsageChart | 24 data points with daytime peak pattern |
| ProjectList | 3 projects (Production, Staging, Red Team) with API keys |
| RuleBuilder | 5 default rules (SQLi, Jailbreak, PII, System Prompt, Base64) |
| RedTeamFuzzer | 12 attack strategies simulated locally |
| RagScanner | 8 injection detection patterns run client-side |
| ChatWindow | Simulation responses with threat keyword detection |
| MonitoringPanel | 10 audit logs + 4 sessions (2 escalated) |
| ApiKeysSettings | 2 default API keys |

---

## 14. COMMANDS

```bash
# Frontend
npm run dev          # Start dev server on 0.0.0.0:5173
npm run build        # Production build to dist/
npm run preview      # Preview production build

# Backend
cd backend && pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Full stack
./start-all.sh       # Linux/Mac — starts backend + frontend
start-all.bat        # Windows

# Docker
docker-compose up    # Full stack via Docker
```

---

## 15. DESIGN SYSTEM

- **Theme**: Dark cybersecurity aesthetic with CSS variables
- **Colors**: `--bg-primary` (deep navy), `--card-bg` (dark panels), `--text-primary` (white), `--text-muted` (gray)
- **Accents**: Cyan (`#06b6d4`) for primary actions, Red (`#ef4444`) for threats/blocks, Green (`#10b981`) for safe/allowed, Yellow (`#eab308`) for warnings/flags, Purple (`#8b5cf6`) for ML/models
- **Typography**: System sans-serif for body, `font-mono` / JetBrains Mono for code/terminal, Orbitron for headings
- **Animations**: Framer Motion for page transitions, CSS animations for pulses/glows, SVG animations for radar/nodes
- **Glass panels**: `backdrop-blur` + semi-transparent backgrounds + border accents
- **Console**: Terminal green (`--console-text-default`), color-coded log types (ERR=red, WARN=yellow, SEC=green, EXEC=blue)
