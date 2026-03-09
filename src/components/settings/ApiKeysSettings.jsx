import React, { useState } from 'react';
import { KeyRound, Plus, Trash2 } from 'lucide-react';

const ApiKeysSettings = () => {
    // Mock user root keys, separate from specific Project keys
    const [keys, setKeys] = useState([
        { id: '1', name: 'Root Dev Key', key: 'sk-root4a9c8f2b1d3...', created: '2026-03-01' },
    ]);

    return (
        <div className="flex flex-col h-full">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h2 className="text-xl font-bold flex items-center gap-2"><KeyRound className="text-cyan-400 w-5 h-5" /> User API Keys</h2>
                    <p className="text-sm text-gray-400">Manage API keys that bypass project boundaries for admin access.</p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg text-sm font-semibold transition-colors">
                    <Plus className="w-4 h-4" /> Generate Key
                </button>
            </div>

            <div className="overflow-x-auto rounded-lg border border-gray-700">
                <table className="w-full text-left text-sm text-gray-400">
                    <thead className="bg-gray-900 border-b border-gray-700 text-xs uppercase font-semibold text-gray-300">
                        <tr>
                            <th className="px-6 py-3">Key Name</th>
                            <th className="px-6 py-3">Token Pattern</th>
                            <th className="px-6 py-3">Created</th>
                            <th className="px-6 py-3 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {keys.map((k) => (
                            <tr key={k.id} className="border-b border-gray-700 last:border-0 hover:bg-gray-800/50">
                                <td className="px-6 py-4 font-semibold text-gray-200">{k.name}</td>
                                <td className="px-6 py-4 font-mono text-cyan-400">{k.key}</td>
                                <td className="px-6 py-4 text-xs">{k.created}</td>
                                <td className="px-6 py-4 text-right">
                                    <button className="text-red-400 hover:text-red-300 transition-colors p-2 rounded hover:bg-red-900/30">
                                        <Trash2 className="w-4 h-4" />
                                    </button>
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
