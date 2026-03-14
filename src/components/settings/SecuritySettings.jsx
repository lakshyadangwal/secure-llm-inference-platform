import React, { useState, useEffect } from 'react';
import { ShieldCheck, Save, Check } from 'lucide-react';

const STORAGE_KEY = 'ns_security_settings';

const DEFAULTS = {
    forcePiiRedaction: true,
    auditLevel: 'verbose',
};

const SecuritySettings = () => {
    const [settings, setSettings] = useState(DEFAULTS);
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            try { setSettings(JSON.parse(stored)); } catch { }
        }
    }, []);

    const handleSave = () => {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
    };

    return (
        <div className="flex flex-col h-full">
            <div className="mb-6">
                <h2 className="text-xl font-bold flex items-center gap-2"><ShieldCheck className="text-green-400 w-5 h-5" /> Global Security Controls</h2>
                <p className="text-sm text-gray-400">Enforce global overrides for all projects on this platform instance.</p>
            </div>

            <div className="space-y-6">
                <div className="p-4 bg-gray-900 border border-gray-700 rounded-xl flex items-center justify-between">
                    <div>
                        <h4 className="font-semibold text-gray-200">Force PII Redaction Everywhere</h4>
                        <p className="text-xs text-gray-500">Overrides project settings to ensure PII is always masked.</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            className="sr-only peer"
                            checked={settings.forcePiiRedaction}
                            onChange={(e) => { setSettings(s => ({ ...s, forcePiiRedaction: e.target.checked })); setSaved(false); }}
                        />
                        <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-500"></div>
                    </label>
                </div>

                <div className="p-4 bg-gray-900 border border-gray-700 rounded-xl">
                    <h4 className="font-semibold text-gray-200 mb-2">Audit Logging Level</h4>
                    <select
                        className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                        value={settings.auditLevel}
                        onChange={(e) => { setSettings(s => ({ ...s, auditLevel: e.target.value })); setSaved(false); }}
                    >
                        <option value="critical">Critical Only (Less noise, ignores minor blocks)</option>
                        <option value="standard">Standard (Logs all threats and blocks)</option>
                        <option value="verbose">Verbose (Logs all traffic and metadata)</option>
                    </select>
                </div>

                <div className="flex justify-end pt-4">
                    <button
                        onClick={handleSave}
                        className={`flex items-center gap-2 px-6 py-2 rounded-lg font-semibold transition-colors ${saved ? 'bg-green-700 text-green-200' : 'bg-green-600 hover:bg-green-500 text-white'}`}
                    >
                        {saved ? <><Check className="w-4 h-4" /> Saved</> : <><Save className="w-4 h-4" /> Save Global Policies</>}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default SecuritySettings;
