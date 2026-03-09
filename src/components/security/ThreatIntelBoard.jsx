import React, { useEffect, useState } from 'react';
import ThreatCard from './ThreatCard';
import { Globe } from 'lucide-react';

const ThreatIntelBoard = () => {
    const [threats, setThreats] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch('http://localhost:8000/api/threat-intel/')
            .then(res => res.json())
            .then(data => {
                if (data.threats) setThreats(data.threats);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    }, []);

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-md h-full flex flex-col">
            <div className="flex items-center gap-2 mb-6 text-xl">
                <Globe className="text-blue-500 w-6 h-6" />
                <h2 className="font-bold text-gray-200">Global Threat Intelligence</h2>
            </div>

            <p className="text-sm text-gray-400 mb-6">Live feeds of known malicious actors and indicators of compromise (IoCs).</p>

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
