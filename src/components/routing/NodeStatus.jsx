import React from 'react';
import { Activity, AlertTriangle } from 'lucide-react';

const NodeStatus = ({ node }) => {
    const loadPct = Math.round(node.current_load);
    let statusColor = "text-green-400 bg-green-900/30 border border-green-800";
    let icon = <Activity className="w-3 h-3" />;

    if (loadPct > 80) {
        statusColor = "text-orange-400 bg-orange-900/30 border border-orange-800";
        icon = <AlertTriangle className="w-3 h-3" />;
    }
    if (node.status === 'offline') {
        statusColor = "text-red-400 bg-red-900/30 border border-red-800";
    }

    return (
        <div className="bg-gray-900 p-4 rounded-lg border border-gray-700 flex flex-col gap-3">
            <div className="flex justify-between items-center">
                <span className="font-mono text-sm font-semibold text-gray-200">{node.id}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] uppercase tracking-wider flex items-center gap-1 font-bold ${statusColor}`}>
                    {icon} {node.status}
                </span>
            </div>

            <div className="text-xs text-gray-400 font-mono mb-1">
                Hosted: <span className="text-purple-400">{node.model}</span>
            </div>

            <div className="flex flex-col gap-1">
                <div className="flex justify-between text-xs text-gray-500 font-mono">
                    <span>Sat: {loadPct}%</span>
                    <span>{node.capacity} CU</span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-1.5 overflow-hidden">
                    <div
                        className={`h-full transition-all duration-500 ease-out ${loadPct > 80 ? 'bg-orange-500' : 'bg-cyan-500'}`}
                        style={{ width: `${loadPct}%` }}
                    />
                </div>
            </div>
        </div>
    );
};

export default NodeStatus;
