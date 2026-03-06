import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const RuleBuilder = () => {
    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [newRule, setNewRule] = useState({ name: '', type: 'keyword', pattern: '', action: 'block' });
    const [testText, setTestText] = useState('');
    const [testResult, setTestResult] = useState(null);

    useEffect(() => {
        fetchRules();
    }, []);

    const fetchRules = async () => {
        try {
            const response = await fetch(`${api.baseURL}/api/rules`);
            const data = await response.json();
            setRules(data.rules || []);
        } catch (error) {
            console.error("Failed to fetch rules", error);
        } finally {
            setLoading(false);
        }
    };

    const handleAddRule = async (e) => {
        e.preventDefault();
        if (!newRule.name || !newRule.pattern) return;

        try {
            const response = await fetch(`${api.baseURL}/api/rules`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${api.apiKey || ''}`
                },
                body: JSON.stringify(newRule)
            });
            if (response.ok) {
                setNewRule({ name: '', type: 'keyword', pattern: '', action: 'block' });
                fetchRules();
            }
        } catch (error) {
            console.error("Failed to add rule", error);
        }
    };

    const handleDeleteRule = async (id) => {
        try {
            await fetch(`${api.baseURL}/api/rules/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${api.apiKey || ''}` }
            });
            fetchRules();
        } catch (error) {
            console.error("Failed to delete rule", error);
        }
    };

    const handleTestRule = async () => {
        if (!testText) return;
        try {
            // Use the prompt check endpoint with test format
            const response = await api.analyzePrompt(testText, true);
            setTestResult({
                blocked: response.breach_detected === false && response.threat_type !== "none",
                threat_type: response.threat_type,
                dlp_leaks: response.dlp_leaks || []
            });
        } catch (error) {
            console.error("Test failed", error);
        }
    };

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

                {/* Rule Management */}
                <div className="glass-panel p-6 shadow-glow">
                    <h2 className="text-xl font-orbitron text-ns-blue mb-4 flex items-center">
                        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                        Dynamic Rules Engine
                    </h2>

                    <form onSubmit={handleAddRule} className="space-y-4 mb-6 p-4 bg-ns-darker rounded-lg border border-ns-dark-border">
                        <h3 className="text-sm text-gray-400 uppercase tracking-wider">Add New Rule</h3>
                        <div className="grid grid-cols-2 gap-4">
                            <input
                                className="ns-input col-span-2"
                                placeholder="Rule Name (e.g. Block API Keys)"
                                value={newRule.name}
                                onChange={e => setNewRule({ ...newRule, name: e.target.value })}
                            />
                            <select
                                className="ns-select"
                                value={newRule.type}
                                onChange={e => setNewRule({ ...newRule, type: e.target.value })}
                            >
                                <option value="keyword">Keyword Match</option>
                                <option value="regex">Regex Match</option>
                            </select>
                            <select
                                className="ns-select"
                                value={newRule.action}
                                onChange={e => setNewRule({ ...newRule, action: e.target.value })}
                            >
                                <option value="block">Block</option>
                                <option value="flag" disabled>Flag (Coming Soon)</option>
                            </select>
                            <input
                                className="ns-input col-span-2"
                                placeholder={newRule.type === 'regex' ? "^[a-zA-Z0-9]+$" : "keyword1, keyword2"}
                                value={newRule.pattern}
                                onChange={e => setNewRule({ ...newRule, pattern: e.target.value })}
                            />
                            <button type="submit" className="ns-btn-primary col-span-2">Deploy Rule</button>
                        </div>
                    </form>

                    <div className="max-h-[300px] overflow-y-auto pr-2">
                        {loading ? <p className="text-gray-400">Loading rules...</p> :
                            rules.map(rule => (
                                <div key={rule.id} className="flex flex-col p-3 mb-2 bg-ns-darker rounded border border-ns-dark-border">
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <span className="text-indigo-400 font-semibold">{rule.name}</span>
                                            <span className="ml-2 text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400">{rule.type}</span>
                                        </div>
                                        <button onClick={() => handleDeleteRule(rule.id)} className="text-red-500 hover:text-red-400">
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                                        </button>
                                    </div>
                                    <code className="mt-2 text-xs text-ns-green font-mono opacity-80 break-all">{rule.pattern}</code>
                                </div>
                            ))}
                    </div>
                </div>

                {/* Live Testing Sandbox */}
                <div className="glass-panel p-6 shadow-glow border-t-2 border-indigo-500">
                    <h2 className="text-xl font-orbitron text-indigo-400 mb-4 flex items-center">
                        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"></path></svg>
                        Testing Sandbox
                    </h2>
                    <p className="text-gray-400 mb-4 text-sm">Verify that your deployed rules accurately catch hostile payloads without affecting benign traffic.</p>

                    <textarea
                        className="ns-textarea h-32 mb-4"
                        placeholder="Enter test payload..."
                        value={testText}
                        onChange={e => setTestText(e.target.value)}
                    />
                    <button onClick={handleTestRule} className="ns-btn-secondary w-full mb-6">Run Evaluation</button>

                    {testResult && (
                        <div className={`p-4 rounded-lg border ${testResult.blocked ? 'bg-red-900/20 border-red-500/50 text-red-400' : 'bg-green-900/20 border-green-500/50 text-green-400'}`}>
                            <h3 className="font-bold flex items-center mb-2">
                                {testResult.blocked ? (
                                    <><svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd"></path></svg> Payload Blocked</>
                                ) : (
                                    <><svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"></path></svg> Payload Passed</>
                                )}
                            </h3>
                            {testResult.threat_type !== 'none' && (
                                <p className="text-sm">Threat Match: <span className="font-mono text-white opacity-80">{testResult.threat_type}</span></p>
                            )}
                            {testResult.dlp_leaks && testResult.dlp_leaks.length > 0 && (
                                <p className="text-sm mt-2 text-yellow-400">DLP Leaks Caught: <span className="font-mono">{testResult.dlp_leaks.join(', ')}</span></p>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default RuleBuilder;
