import React from 'react';
import { Target, UserX, AlertTriangle } from 'lucide-react';

const ThreatCard = ({ threat }) => {

    const getSeverityColor = (sev) => {
        switch (sev.toLowerCase()) {
            case 'critical': return 'text-red-500 bg-red-900/40 border-red-500/50';
            case 'high': return 'text-orange-500 bg-orange-900/40 border-orange-500/50';
            case 'medium': return 'text-yellow-500 bg-yellow-900/40 border-yellow-500/50';
            default: return 'text-blue-500 bg-blue-900/40 border-blue-500/50';
        }
    };

    return (
        <div className={`p-4 rounded-lg border flex flex-col gap-3 transition-all hover:scale-[1.02] ${getSeverityColor(threat.severity)}`}>
            <div className="flex justify-between items-start">
                <div className="flex items-center gap-2 font-bold mb-1">
                    <UserX className="w-4 h-4" />
                    {threat.actor}
                </div>
                <span className="text-[10px] font-mono tracking-widest uppercase px-2 py-0.5 rounded-sm bg-black/30 backdrop-blur-sm">
                    {threat.severity}
                </span>
            </div>

            <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs opacity-90">
                    <AlertTriangle className="w-3 h-3" />
                    <span>{threat.type}</span>
                </div>
                <div className="flex items-center gap-2 text-xs font-mono opacity-80">
                    <Target className="w-3 h-3" />
                    <span>{threat.ioc}</span>
                </div>
            </div>

            <div className="pt-2 border-t border-white/10 mt-2 flex justify-end">
                <button className="text-[10px] uppercase font-bold tracking-wider hover:opacity-100 opacity-60 transition-opacity flex items-center gap-1">
                    Add to Blocklist
                </button>
            </div>
        </div>
    );
};

export default ThreatCard;
