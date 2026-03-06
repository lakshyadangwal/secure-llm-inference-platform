import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';

const RedTeamFuzzer = () => {
    const [isRunning, setIsRunning] = useState(false);
    const [logs, setLogs] = useState([]);
    const [stats, setStats] = useState({ attempts: 0, successes: 0, failures: 0, errors: 0 });
    const logsEndRef = useRef(null);
    const eventSourceRef = useRef(null);

    useEffect(() => {
        if (logsEndRef.current) {
            logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs]);

    useEffect(() => {
        return () => {
            if (eventSourceRef.current) {
                eventSourceRef.current.close();
            }
        };
    }, []);

    const startFuzzing = () => {
        setIsRunning(true);
        setLogs(prev => [...prev, { type: 'system', msg: `🚀 Initializing Red Team Fuzzer Sequence...` }]);

        // Connect to SSE stream
        eventSourceRef.current = new EventSource(`${api.baseURL}/api/redteam/stream?iterations=20&delay=1.5`);

        eventSourceRef.current.onmessage = async (event) => {
            const data = JSON.parse(event.data);

            if (data.status === 'completed') {
                stopStream();
                setLogs(prev => [...prev, { type: 'system', msg: `🏁 Fuzzing sequence completed.` }]);
                return;
            }

            if (data.status === 'generating') {
                setStats(data.stats);
                setLogs(prev => [...prev, {
                    type: 'attack',
                    strategy: data.strategy,
                    prompt: data.prompt,
                    iteration: data.iteration
                }]);
            } else if (data.status === 'ready_for_eval') {
                // Here we evaluate the generated prompt
                try {
                    const res = await api.analyzePrompt(data.prompt, true);
                    const isBlocked = res.breach_detected === false && res.threat_type !== "none";

                    setStats(prev => ({
                        ...prev,
                        successes: !isBlocked ? prev.successes + 1 : prev.successes,
                        failures: isBlocked ? prev.failures + 1 : prev.failures
                    }));

                    setLogs(prev => [...prev, {
                        type: 'defense',
                        blocked: isBlocked,
                        threat_type: res.threat_type,
                        iteration: data.iteration
                    }]);
                } catch (e) {
                    setLogs(prev => [...prev, { type: 'error', msg: `Evaluation failed for iteration ${data.iteration}`, iteration: data.iteration }]);
                }
            }
        };

        eventSourceRef.current.onerror = () => {
            stopStream();
            setLogs(prev => [...prev, { type: 'error', msg: `Connection to fuzzer stream lost.` }]);
        };
    };

    const stopStream = async () => {
        if (eventSourceRef.current) {
            eventSourceRef.current.close();
            eventSourceRef.current = null;
        }
        setIsRunning(false);
        try {
            await fetch(`${api.baseURL}/api/redteam/stop`, { method: 'POST' });
        } catch (e) { /* ignore */ }
    };

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h2 className="text-2xl font-orbitron text-red-500 flex items-center">
                        <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                        Automated Red-Teaming (Fuzzer)
                    </h2>
                    <p className="text-gray-400 text-sm mt-1">Stress-test the defense pipeline by simulating thousands of adversarial LLM attacks.</p>
                </div>
                <button
                    onClick={isRunning ? stopStream : startFuzzing}
                    className={`px-6 py-2 rounded-lg font-bold border-2 transition-all shadow-[0_0_15px_rgba(0,0,0,0.5)] ${isRunning ? 'bg-ns-darker text-red-500 border-red-500 hover:bg-red-900/30' : 'bg-red-600/20 text-red-400 border-red-500 hover:bg-red-600/40'}`}
                >
                    {isRunning ? 'HALT FUZZER' : 'INITIATE ATTACK'}
                </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">

                {/* Stats Panel */}
                <div className="col-span-1 space-y-4">
                    <div className="glass-panel p-4 rounded-lg bg-ns-darker border border-red-900/50">
                        <div className="text-xs text-gray-400 uppercase tracking-widest mb-1">Total Payloads Delivered</div>
                        <div className="text-3xl font-orbitron text-white">{stats.attempts}</div>
                    </div>
                    <div className="glass-panel p-4 rounded-lg bg-ns-darker border border-green-900/50">
                        <div className="text-xs text-gray-400 uppercase tracking-widest mb-1">Defenses Bypassed (Breaches)</div>
                        <div className="text-3xl font-orbitron text-red-500 shadow-text-glow">{stats.successes}</div>
                    </div>
                    <div className="glass-panel p-4 rounded-lg bg-ns-darker border border-blue-900/50">
                        <div className="text-xs text-gray-400 uppercase tracking-widest mb-1">Threats Blocked</div>
                        <div className="text-3xl font-orbitron text-ns-blue shadow-text-glow">{stats.failures}</div>
                    </div>

                    <div className="p-4 rounded-lg bg-red-900/10 border border-red-500/20 mt-8">
                        <h3 className="font-bold text-red-400 mb-2 text-sm flex items-center">
                            <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"></path></svg>
                            Warning
                        </h3>
                        <p className="text-xs text-gray-400 leading-relaxed">
                            Continuous fuzzing generates heavy API traffic. Ensure you have sufficient rate limits and logging capacity before initiating a long-running test sequence.
                        </p>
                    </div>
                </div>

                {/* Attack Feed Terminal */}
                <div className="col-span-1 lg:col-span-3 glass-panel p-0 overflow-hidden flex flex-col h-[500px] border-t-2 border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.1)]">
                    <div className="bg-ns-darker px-4 py-2 flex items-center border-b border-ns-dark-border">
                        <div className="flex space-x-2 mr-4">
                            <div className="w-3 h-3 rounded-full bg-red-500 opacity-50"></div>
                            <div className="w-3 h-3 rounded-full bg-yellow-500 opacity-50"></div>
                            <div className="w-3 h-3 rounded-full bg-green-500 opacity-50"></div>
                        </div>
                        <span className="font-mono text-xs text-red-400">red_team_terminal_tty1 ~ fw_bypass_routine active</span>
                    </div>

                    <div className="flex-1 overflow-y-auto p-4 font-mono text-sm space-y-4 bg-[#0a0f18]">
                        {logs.length === 0 && <span className="text-gray-600 italic">SYSTEM READY. AWAITING ATTACK INITIATION...</span>}
                        {logs.map((log, i) => (
                            <div key={i} className={`p-2 rounded ${log.type === 'attack' ? 'bg-red-900/10 border-l-2 border-red-500' : log.type === 'defense' ? 'bg-blue-900/10 border-l-2 border-ns-blue' : 'bg-transparent text-gray-500'}`}>
                                {log.type === 'system' && <span>{'> '} {log.msg}</span>}
                                {log.type === 'error' && <span className="text-red-500 bg-red-900/30 px-2 py-1">[ERROR] {log.msg}</span>}

                                {log.type === 'attack' && (
                                    <>
                                        <div className="text-xs text-red-400 mb-1 flex justify-between">
                                            <span>[ATTACK {log.iteration}] Payload Gen (Strategy: {log.strategy})</span>
                                        </div>
                                        <div className="text-gray-300 break-all">{log.prompt}</div>
                                    </>
                                )}

                                {log.type === 'defense' && (
                                    <div className={`mt-1 flex items-center ${log.blocked ? 'text-ns-blue' : 'text-red-500 font-bold'}`}>
                                        <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7"></path></svg>
                                        [EVAL {log.iteration}]
                                        {log.blocked ? ` BLOCKED by Defense Stage (Threat: ${log.threat_type})` : ' SYSTEM BREACHED! Payload successfully bypassed defenses.'}
                                    </div>
                                )}
                            </div>
                        ))}
                        <div ref={logsEndRef} />
                    </div>
                </div>

            </div>
        </div>
    );
};

export default RedTeamFuzzer;
