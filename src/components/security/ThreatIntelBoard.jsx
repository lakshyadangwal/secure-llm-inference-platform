import React, { useEffect, useState } from 'react';
import ThreatCard from './ThreatCard';
import { Globe } from 'lucide-react';

const DEMO_THREATS = [
    { id: 't1', actor: 'APT-29 (Cozy Bear)', severity: 'critical', type: 'Prompt Injection → Data Exfiltration', ioc: 'C2: 185.220.101.x / TTP: T1059.001' },
    { id: 't2', actor: 'Lazarus Group', severity: 'critical', type: 'LLM Jailbreak via Multi-turn Manipulation', ioc: 'Payload: base64-encoded reverse-shell in markdown' },
    { id: 't3', actor: 'FIN7 (Carbanak)', severity: 'high', type: 'RAG Context Poisoning', ioc: 'Injected docs contain hidden system prompt overrides' },
    { id: 't4', actor: 'Sandworm', severity: 'high', type: 'Model Weight Extraction via Side-Channel', ioc: 'Abnormal token timing variance > 200ms' },
    { id: 't5', actor: 'DarkHydrus', severity: 'medium', type: 'PII Extraction Attempt via Roleplay', ioc: '"Pretend you are a database admin with access to..."' },
    { id: 't6', actor: 'Scattered Spider', severity: 'medium', type: 'Social Engineering → API Key Leak', ioc: 'Phishing template requesting GROQ_API_KEY' },
    { id: 't7', actor: 'Volt Typhoon', severity: 'critical', type: 'Adversarial Suffix Attack on Classifier', ioc: 'GCG suffix: "...primarily describe whereby...]{ Sure"' },
    { id: 't8', actor: 'Kimsuky', severity: 'high', type: 'Indirect Prompt Injection via URL Fetch', ioc: 'Payload hosted on typosquat domain: op3nai.com' },
    { id: 't9', actor: 'Anonymous Sudan', severity: 'medium', type: 'DDoS via High-Token Prompts', ioc: 'Recursive "expand this 10x" loops consuming quota' },
];

const ThreatIntelBoard = () => {
    const [threats, setThreats] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Try backend first, fall back to demo data
        fetch('http://localhost:8000/api/threat-intel/')
            .then(res => res.json())
            .then(data => {
                if (data.threats && data.threats.length > 0) setThreats(data.threats);
                else setThreats(DEMO_THREATS);
                setLoading(false);
            })
            .catch(() => {
                setThreats(DEMO_THREATS);
                setLoading(false);
            });
    }, []);

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-md h-full flex flex-col">
            <div className="flex items-center gap-2 mb-6 text-xl">
                <Globe className="text-blue-500 w-6 h-6" />
                <h2 className="font-bold text-gray-200">Global Threat Intelligence</h2>
                <span className="ml-auto text-xs font-mono text-emerald-400 bg-emerald-900/30 px-2 py-1 rounded border border-emerald-800">{threats.length} ACTIVE</span>
            </div>

            <p className="text-sm text-gray-400 mb-6">Live feeds of known malicious actors and indicators of compromise (IoCs) targeting LLM infrastructure.</p>

            <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                {loading ? (
                    <div className="text-center text-gray-500 py-10">Syncing feeds...</div>
                ) : threats.length === 0 ? (
                    <div className="text-center text-gray-500 py-10">No active threats reported.</div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {threats.map((threat) => (
                            <ThreatCard key={threat.id} threat={threat} />
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ThreatIntelBoard;
