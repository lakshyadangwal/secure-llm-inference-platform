import React, { useState } from 'react';
import { Fingerprint, Save } from 'lucide-react';

const PiiSettings = () => {
    const [settings, setSettings] = useState({
        mask_emails: true,
        mask_phones: true,
        mask_ssn: true,
        mask_credit_cards: true,
        action: 'redact'
    });

    const [saved, setSaved] = useState(false);

    const toggleSetting = (key) => {
        setSettings(prev => ({ ...prev, [key]: !prev[key] }));
        setSaved(false);
    };

    const handleSave = () => {
        // In reality, POST to backend to save
        setTimeout(() => setSaved(true), 500);
    };

    const Switch = ({ checked, onChange, label }) => (
        <label className="flex items-center justify-between cursor-pointer p-3 bg-gray-900 rounded-lg hover:bg-gray-800 transition-colors border border-gray-700">
            <span className="text-sm font-semibold text-gray-300">{label}</span>
            <div className="relative">
                <input type="checkbox" className="sr-only peer" checked={checked} onChange={onChange} />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500"></div>
            </div>
        </label>
    );

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-md h-full flex flex-col">
            <div className="flex items-center gap-2 mb-6 text-xl">
                <Fingerprint className="text-purple-500 w-6 h-6" />
                <h2 className="font-bold text-gray-200">Data Loss Prevention (DLP)</h2>
            </div>

            <p className="text-sm text-gray-400 mb-6">Configure which sensitive data elements should be intercepted before reaching the LLM, or blocked entirely.</p>

            <div className="flex-1 space-y-3">
                <Switch
                    label="Mask Email Addresses"
                    checked={settings.mask_emails}
                    onChange={() => toggleSetting('mask_emails')}
                />
                <Switch
                    label="Mask Phone Numbers"
                    checked={settings.mask_phones}
                    onChange={() => toggleSetting('mask_phones')}
                />
                <Switch
                    label="Mask SSN / National IDs"
                    checked={settings.mask_ssn}
                    onChange={() => toggleSetting('mask_ssn')}
                />
                <Switch
                    label="Mask Credit Cards"
                    checked={settings.mask_credit_cards}
                    onChange={() => toggleSetting('mask_credit_cards')}
                />

                <div className="mt-6 pt-6 border-t border-gray-700">
                    <label className="block text-sm font-semibold text-gray-300 mb-3">Interception Action</label>
                    <select
                        className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-white focus:outline-none focus:border-purple-500"
                        value={settings.action}
                        onChange={(e) => {
                            setSettings(prev => ({ ...prev, action: e.target.value }));
                            setSaved(false);
                        }}
                    >
                        <option value="redact">Redact and Synthesize (Replace with tokens)</option>
                        <option value="block">Hard Block (Reject request entirely)</option>
                    </select>
                </div>
            </div>

            <div className="mt-6 flex justify-end">
                <button
                    onClick={handleSave}
                    className="flex items-center gap-2 px-6 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-semibold transition-colors"
                >
                    <Save className="w-4 h-4" />
                    {saved ? "Saved Data" : "Save Policies"}
                </button>
            </div>
        </div>
    );
};

export default PiiSettings;
