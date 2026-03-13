import React, { useState, useEffect } from 'react';
import { Cpu, Save, Check } from 'lucide-react';

const STORAGE_KEY = 'ns_model_prefs';

const DEFAULTS = {
    primaryModel: 'llama3.1:latest',
    semanticCaching: true,
};

const ModelPreferences = () => {
    const [prefs, setPrefs] = useState(DEFAULTS);
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            try { setPrefs(JSON.parse(stored)); } catch { }
        }
    }, []);

    const handleSave = () => {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
    };

    return (
        <div className="flex flex-col h-full">
            <div className="mb-6">
                <h2 className="text-xl font-bold flex items-center gap-2"><Cpu className="text-purple-400 w-5 h-5" /> Model Preferences</h2>
                <p className="text-sm text-gray-400">Configure default fallback models and semantic cache layers.</p>
            </div>

            <div className="space-y-6">
                <div className="p-4 bg-gray-900 border border-gray-700 rounded-xl">
                    <h4 className="font-semibold text-gray-200 mb-2">Primary Hosted Model</h4>
                    <p className="text-xs text-gray-500 mb-3">Model used when projects do not specify one.</p>
                    <select
                        className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                        value={prefs.primaryModel}
                        onChange={(e) => { setPrefs(p => ({ ...p, primaryModel: e.target.value })); setSaved(false); }}
                    >
                        <option value="llama3.1:latest">Llama 3.1 (8B)</option>
                        <option value="phi:latest">Phi-2 (Local Compute)</option>
                        <option value="mistral:latest">Mistral (7B)</option>
                        <option value="deepseek:latest">DeepSeek (6.7B)</option>
                    </select>
                </div>

                <div className="p-4 bg-gray-900 border border-gray-700 rounded-xl flex items-center justify-between">
                    <div>
                        <h4 className="font-semibold text-gray-200">Semantic Layer Caching</h4>
                        <p className="text-xs text-gray-500 max-w-[80%]">Skip inference completely if exact semantic meaning has been seen recently. Drastically lowers latency and cost.</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            className="sr-only peer"
                            checked={prefs.semanticCaching}
                            onChange={(e) => { setPrefs(p => ({ ...p, semanticCaching: e.target.checked })); setSaved(false); }}
                        />
                        <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-500"></div>
                    </label>
                </div>

                <div className="flex justify-end pt-4">
                    <button
                        onClick={handleSave}
                        className={`flex items-center gap-2 px-6 py-2 rounded-lg font-semibold transition-colors ${saved ? 'bg-purple-700 text-purple-200' : 'bg-purple-600 hover:bg-purple-500 text-white'}`}
                    >
                        {saved ? <><Check className="w-4 h-4" /> Saved</> : <><Save className="w-4 h-4" /> Save Hardware Config</>}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ModelPreferences;
