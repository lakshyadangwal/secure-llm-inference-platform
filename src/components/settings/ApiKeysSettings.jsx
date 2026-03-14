import React, { useState, useEffect } from 'react';
import { KeyRound, Plus, Trash2, Eye, EyeOff, Copy, Check } from 'lucide-react';

const STORAGE_KEY = 'ns_api_keys';

const DEFAULT_KEYS = [
    { id: '1', name: 'Root Dev Key', key: 'sk-root4a9c8f2b1d3e4f5a6b7c8d9e0f1a2b3c4', created: '2026-03-01' },
    { id: '2', name: 'CI/CD Pipeline', key: 'sk-cicd7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b', created: '2026-03-05' },
];

const ApiKeysSettings = () => {
    const [keys, setKeys] = useState([]);
    const [visibleKeys, setVisibleKeys] = useState({});
    const [copied, setCopied] = useState(null);

    useEffect(() => {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            try { setKeys(JSON.parse(stored)); } catch { setKeys(DEFAULT_KEYS); }
        } else {
            setKeys(DEFAULT_KEYS);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(DEFAULT_KEYS));
        }
    }, []);

    const saveKeys = (updated) => {
        setKeys(updated);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    };

    const generateKey = () => {
        const newKey = {
            id: String(Date.now()),
            name: `Key ${keys.length + 1}`,
            key: 'sk-' + crypto.randomUUID().replace(/-/g, '').slice(0, 32),
            created: new Date().toISOString().slice(0, 10),
        };
        saveKeys([...keys, newKey]);
    };

    const deleteKey = (id) => {
        saveKeys(keys.filter(k => k.id !== id));
    };

    const toggleVisibility = (id) => {
        setVisibleKeys(prev => ({ ...prev, [id]: !prev[id] }));
    };

    const copyKey = (key, id) => {
        navigator.clipboard.writeText(key);
        setCopied(id);
        setTimeout(() => setCopied(null), 2000);
    };

    const maskKey = (key) => key.slice(0, 7) + '••••••••••••••••••••';

    return (
        <div className="flex flex-col h-full">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h2 className="text-xl font-bold flex items-center gap-2"><KeyRound className="text-cyan-400 w-5 h-5" /> User API Keys</h2>
                    <p className="text-sm text-gray-400">Manage API keys that bypass project boundaries for admin access.</p>
                </div>
                <button
                    onClick={generateKey}
                    className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-semibold transition-colors"
                >
                    <Plus className="w-4 h-4" /> Generate Key
                </button>
            </div>

            <div className="overflow-x-auto rounded-lg border border-gray-700">
                <table className="w-full text-left text-sm text-gray-400">
                    <thead className="bg-gray-900 border-b border-gray-700 text-xs uppercase font-semibold text-gray-300">
                        <tr>
                            <th className="px-6 py-3">Key Name</th>
                            <th className="px-6 py-3">Token</th>
                            <th className="px-6 py-3">Created</th>
                            <th className="px-6 py-3 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {keys.map((k) => (
                            <tr key={k.id} className="border-b border-gray-700 last:border-0 hover:bg-gray-800/50">
                                <td className="px-6 py-4 font-semibold text-gray-200">{k.name}</td>
                                <td className="px-6 py-4 font-mono text-cyan-400">
                                    {visibleKeys[k.id] ? k.key : maskKey(k.key)}
                                </td>
                                <td className="px-6 py-4 text-xs">{k.created}</td>
                                <td className="px-6 py-4 text-right">
                                    <div className="flex items-center justify-end gap-1">
                                        <button onClick={() => toggleVisibility(k.id)}
                                            className="text-gray-400 hover:text-white transition-colors p-2 rounded hover:bg-gray-700">
                                            {visibleKeys[k.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                        </button>
                                        <button onClick={() => copyKey(k.key, k.id)}
                                            className="text-gray-400 hover:text-white transition-colors p-2 rounded hover:bg-gray-700">
                                            {copied === k.id ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                                        </button>
                                        <button onClick={() => deleteKey(k.id)}
                                            className="text-red-400 hover:text-red-300 transition-colors p-2 rounded hover:bg-red-900/30">
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ApiKeysSettings;
