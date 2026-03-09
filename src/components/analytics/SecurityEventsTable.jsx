import React from 'react';
import { ShieldAlert } from 'lucide-react';

const SecurityEventsTable = ({ events }) => {

    const getSeverityBadge = (severity) => {
        const base = "px-2 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ";
        switch (severity.toLowerCase()) {
            case 'critical': return base + "bg-red-900/50 text-red-400 border border-red-800";
            case 'warning': return base + "bg-yellow-900/50 text-yellow-500 border border-yellow-800";
            default: return base + "bg-blue-900/50 text-blue-400 border border-blue-800";
        }
    };

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-md h-full flex flex-col">
            <div className="flex items-center gap-2 mb-6">
                <ShieldAlert className="text-red-400 w-5 h-5" />
                <h3 className="font-semibold text-gray-200">Recent Security Events</h3>
            </div>

            <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                {events.length === 0 ? (
                    <div className="text-center text-sm text-gray-500 py-10">
                        No recent security events detected.
                    </div>
                ) : (
                    <div className="flex flex-col gap-3">
                        {events.map((evt, idx) => (
                            <div key={idx} className="bg-gray-900 p-3 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors flex flex-col gap-2">
                                <div className="flex justify-between items-start">
                                    <span className="text-xs font-mono text-gray-300 font-semibold">{evt.event_type}</span>
                                    {getSeverityBadge(evt.severity)}
                                </div>
                                <p className="text-xs text-gray-400">{evt.details}</p>
                                <span className="text-[10px] text-gray-500 font-mono mt-1">
                                    {new Date(evt.timestamp).toLocaleString()}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default SecurityEventsTable;
