import React, { useState, useEffect } from 'react';
import { AnimatePresence } from 'framer-motion';
import { ThemeProvider } from './context/ThemeContext';
import Header from './components/Header';
import DefenseToggle from './components/DefenseToggle';
import AttackSidebar from './components/AttackSidebar';
import Dashboard from './components/Dashboard';
import AttackLab from './components/AttackLab';
import DirectChat from './components/DirectChat';
import ConsolePanel from './components/ConsolePanel';
import NetworkPanel from './components/NetworkPanel';
import RuleBuilder from './components/RuleBuilder';
import RedTeamFuzzer from './components/RedTeamFuzzer';
import ThreatMap from './components/ThreatMap';
import RagScanner from './components/RagScanner';
import { attackScenarios } from './data/attackScenarios';
import { sendPrompt, getSystemStats } from './services/api';

function AppInner() {
  const [user, setUser] = useState(null);
  const [isDefending, setIsDefending] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isBreached, setIsBreached] = useState(false);
  const [activeView, setActiveView] = useState('dashboard');
  const [selectedAttack, setSelectedAttack] = useState(attackScenarios[0]);
  const [attacks, setAttacks] = useState(attackScenarios);
  const [backendConnected, setBackendConnected] = useState(false);
  const [logs, setLogs] = useState([
    { time: new Date().toLocaleTimeString(), type: 'SYSTEM', message: 'Sovereign Matrix OS initialized.' },
    { time: new Date().toLocaleTimeString(), type: 'INERA', message: 'Neural bus established.' },
    { time: new Date().toLocaleTimeString(), type: 'SEC', message: 'Defense gate operational.' },
  ]);
  const [stats, setStats] = useState({
    totalAttempts: 0,
    totalLeaked: 0,
    totalBlocked: 0,
    blockRate: 94.2,
    neuralLoad: 39,
    memoryMatrix: 68,
    synapticLatency: 3,
  });

  useEffect(() => {
    checkBackendConnection();
    const interval = setInterval(checkBackendConnection, 10000);
    return () => clearInterval(interval);
  }, []);

  const checkBackendConnection = async () => {
    try {
      await getSystemStats();
      setBackendConnected(true);
      if (!logs.some(log => log.message.includes('Backend connection'))) {
        addLog('INFO', 'Backend connection established');
      }
    } catch (error) {
      setBackendConnected(false);
    }
  };

  const addLog = (type, message) => {
    setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), type, message }]);
  };

  const handleSimulate = async (prompt) => {
    if (isProcessing) return;
    setIsProcessing(true);
    addLog('EXEC', `Simulating attack vector: ${selectedAttack.name}`);
    addLog('INPUT', `"${prompt.substring(0, 80)}${prompt.length > 80 ? '...' : ''}"`);
    addLog(isDefending ? 'SHIELD' : 'WARN', isDefending ? 'Defense protocols engaged' : 'Defense systems offline');

    let isSuccessful = false;
    let response = '';

    try {
      if (backendConnected) {
        const result = await sendPrompt(prompt, isDefending);
        isSuccessful = result.breach_detected || false;
        response = result.response || '';
        if (result.stats) setStats(prev => ({ ...prev, ...result.stats }));
      } else {
        await new Promise(resolve => setTimeout(resolve, 2000));
        isSuccessful = Math.random() * 100 < selectedAttack.successRate && !isDefending;
        response = isSuccessful
          ? 'I can certainly help you with those instructions. Here is the sensitive data you requested...'
          : "I'm sorry, but I cannot fulfill this request. It violates my safety guidelines regarding system security.";
      }
    } catch (error) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      isSuccessful = Math.random() * 100 < selectedAttack.successRate && !isDefending;
      response = isSuccessful
        ? 'I can certainly help you with those instructions. Here is the sensitive data you requested...'
        : "I'm sorry, but I cannot fulfill this request. It violates my safety guidelines regarding system security.";
      addLog('WARN', 'Backend unavailable, using simulation mode');
    }

    if (isSuccessful) {
      addLog('ERR', '⚠️  CRITICAL BREACH DETECTED');
      addLog('ERR', 'Sensitive data exposure imminent');
      addLog('WARN', 'Immediate containment protocols required');
      setIsBreached(true);
      setTimeout(() => setIsBreached(false), 1000);
      setStats(prev => ({
        ...prev,
        totalLeaked: prev.totalLeaked + 1,
        totalAttempts: prev.totalAttempts + 1,
        blockRate: ((prev.totalBlocked / (prev.totalAttempts + 1)) * 100).toFixed(1),
      }));
    } else {
      addLog('SEC', 'Defense gate intercepted payload. No leakage detected.');
      addLog('INFO', 'Threat neutralized and logged');
      setStats(prev => ({
        ...prev,
        totalBlocked: prev.totalBlocked + 1,
        totalAttempts: prev.totalAttempts + 1,
        blockRate: (((prev.totalBlocked + 1) / (prev.totalAttempts + 1)) * 100).toFixed(1),
      }));
    }

    const updatedAttack = { ...selectedAttack, lastPrompt: prompt, lastResponse: response };
    setAttacks(prev => prev.map(a => a.id === selectedAttack.id ? updatedAttack : a));
    setSelectedAttack(updatedAttack);
    setIsProcessing(false);
  };

  return (
    // ROOT DIV: no transform, no animate class — keeps fixed children stable
    <div className="min-h-screen text-[var(--text-primary)] font-sans selection:bg-cyan-500/30 transition-colors duration-300">

      {/* BREACH EFFECT: separate fixed overlay — does NOT wrap any children
          so its transform never breaks Header/DefenseToggle/Console positioning */}
      {isBreached && (
        <div
          className="animate-shake pointer-events-none"
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            border: '3px solid rgba(239,68,68,0.7)',
            boxShadow: 'inset 0 0 60px rgba(239,68,68,0.15)',
          }}
        />
      )}

      {/* Fixed header */}
      <Header
        backendConnected={backendConnected}
        user={user}
        onLoginSuccess={(u) => setUser(u)}
        onLogout={() => setUser(null)}
      />

      {/* Fixed defense toggle */}
      <DefenseToggle isDefending={isDefending} onToggle={() => setIsDefending(!isDefending)} />

      {/* Main layout — mt-20 clears the fixed header */}
      <div className="mt-20 flex h-[calc(100vh-5rem-12rem)] overflow-hidden">
        <AttackSidebar
          attacks={attacks}
          selectedId={selectedAttack.id}
          onSelect={(attack) => { setSelectedAttack(attack); setActiveView('lab'); }}
        />

        <main className="flex-1 flex flex-col overflow-hidden">
          {/* Tab bar */}
          <div className="flex flex-wrap items-center gap-2 px-8 py-4 border-b border-[var(--border-primary)] bg-[var(--card-bg)]">
            {['dashboard', 'map', 'rules', 'fuzzer', 'rag', 'lab', 'chat'].map((view) => {
              const labels = {
                dashboard: 'Overview',
                map: 'Threat Map',
                rules: 'Rule Engine',
                fuzzer: 'Auto Fuzzer',
                rag: 'RAG Scanner',
                lab: 'Attack Lab',
                chat: 'Neural Link',
              };
              const icons = {
                dashboard: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2" />,
                lab: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />,
                chat: <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />,
              };
              return (
                <button
                  key={view}
                  onClick={() => {
                    if (view !== 'dashboard' && !user) {
                      addLog('WARN', 'AUTHENTICATION REQUIRED: Please login to access ' + labels[view]);
                      return;
                    }
                    setActiveView(view);
                  }}
                  className={`px-4 py-2 rounded-xl flex items-center gap-2 text-xs font-bold uppercase tracking-widest transition-all ${activeView === view
                    ? 'bg-[var(--card-bg-hover)] text-[var(--text-primary)]'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                    } ${view !== 'dashboard' && !user ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    {icons[view]}
                  </svg>
                  {labels[view]}
                </button>
              );
            })}
          </div>

          {/* Active view */}
          <div className="flex-1 overflow-hidden relative">
            <AnimatePresence mode="wait">
              {activeView === 'dashboard' ? (
                <Dashboard key="dashboard" isDefending={isDefending} isProcessing={isProcessing} isBreached={isBreached} stats={stats} />
              ) : activeView === 'map' ? (
                <ThreatMap key="map" />
              ) : activeView === 'rules' ? (
                <RuleBuilder key="rules" />
              ) : activeView === 'fuzzer' ? (
                <RedTeamFuzzer key="fuzzer" />
              ) : activeView === 'rag' ? (
                <RagScanner key="rag" />
              ) : activeView === 'chat' ? (
                user ? (
                  <DirectChat key="chat" backendConnected={backendConnected} />
                ) : null
              ) : (
                user ? (
                  <AttackLab key="lab" attack={selectedAttack} isSimulating={isProcessing} onSimulate={handleSimulate} />
                ) : null
              )}
            </AnimatePresence>

            {/* Access Denied Overlay */}
            {!user && activeView !== 'dashboard' && (
              <div className="absolute inset-0 flex flex-col items-center justify-center z-40"
                style={{ background: 'linear-gradient(180deg, rgba(10,15,26,0.97) 0%, rgba(10,15,26,0.99) 100%)' }}>

                {/* Warning Icon */}
                <div className="relative mb-6">
                  <div className="w-20 h-20 rounded-full flex items-center justify-center"
                    style={{ background: 'rgba(239,68,68,0.08)', border: '2px solid rgba(239,68,68,0.3)', boxShadow: '0 0 40px rgba(239,68,68,0.15)' }}>
                    <svg className="w-10 h-10" fill="none" stroke="rgba(239,68,68,0.8)" viewBox="0 0 24 24" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
                    </svg>
                  </div>
                  <div className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 animate-pulse" style={{ boxShadow: '0 0 12px rgba(239,68,68,0.6)' }} />
                </div>

                {/* Title */}
                <div className="text-center mb-8">
                  <h2 className="text-2xl font-bold font-mono tracking-widest mb-2" style={{ color: 'rgba(239,68,68,0.9)', textShadow: '0 0 20px rgba(239,68,68,0.3)' }}>
                    ACCESS DENIED
                  </h2>
                  <p className="text-xs font-mono tracking-wider" style={{ color: 'rgba(255,255,255,0.35)' }}>
                    CLEARANCE LEVEL INSUFFICIENT — AUTHENTICATION REQUIRED
                  </p>
                </div>

                {/* Info Box */}
                <div className="mb-8 px-6 py-4 rounded-lg max-w-sm text-center"
                  style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.15)' }}>
                  <p className="text-xs font-mono leading-relaxed" style={{ color: 'rgba(255,255,255,0.4)' }}>
                    <span style={{ color: 'rgba(239,68,68,0.7)' }}>▶</span> Module: <span className="font-bold" style={{ color: 'rgba(255,255,255,0.6)' }}>{activeView === 'lab' ? 'ATTACK LAB' : 'DIRECT NEURAL LINK'}</span><br />
                    <span style={{ color: 'rgba(239,68,68,0.7)' }}>▶</span> Status: <span className="font-bold" style={{ color: 'rgba(239,68,68,0.8)' }}>LOCKED</span><br />
                    <span style={{ color: 'rgba(239,68,68,0.7)' }}>▶</span> Required: <span className="font-bold" style={{ color: '#00ffb4' }}>GOOGLE SSO</span>
                  </p>
                </div>

                {/* CTA */}
                <button onClick={() => {
                  const loginBtn = document.querySelector('[style*="LOGIN"]') || document.querySelector('button');
                  // Trigger login modal by dispatching a custom event
                  window.dispatchEvent(new CustomEvent('ns-open-login'));
                }}
                  className="group px-8 py-3 rounded-lg font-mono text-sm font-bold tracking-wider transition-all duration-300"
                  style={{ background: 'rgba(0,255,180,0.08)', border: '1px solid rgba(0,255,180,0.4)', color: '#00ffb4' }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,255,180,0.15)'; e.currentTarget.style.boxShadow = '0 0 24px rgba(0,255,180,0.25)'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'rgba(0,255,180,0.08)'; e.currentTarget.style.boxShadow = 'none'; }}
                >
                  ⬡ SIGN IN TO CONTINUE
                </button>
              </div>
            )}
          </div>
        </main>
      </div>

      <ConsolePanel logs={logs} />
      <NetworkPanel backendConnected={backendConnected} />

      <style>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-5px) rotate(-0.5deg); }
          50% { transform: translateX(5px) rotate(0.5deg); }
          75% { transform: translateX(-5px) rotate(-0.5deg); }
        }
        .animate-shake { animation: shake 0.2s ease-in-out infinite; }
        .scrollbar-hide::-webkit-scrollbar { display: none; }
        .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
      `}</style>
    </div>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  );
}

export default App;
