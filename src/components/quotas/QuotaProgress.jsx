import React from 'react';
import { Banknote, Zap } from 'lucide-react';

const QuotaProgress = ({ quota }) => {
    const tokenPct = (quota.tokens_used / quota.token_limit) * 100;
    const spendPct = (quota.spend / quota.budget) * 100;

    const getColor = (pct) => {
        if (pct >= 95) return 'bg-red-500';
        if (pct >= 80) return 'bg-orange-500';
        return 'bg-cyan-500';
    };

    return (
        <div className="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-md flex flex-col gap-4">
            <h3 className="font-bold text-gray-200 text-lg border-b border-gray-700 pb-2">{quota.name}</h3>

            <div className="flex flex-col gap-2">
                <div className="flex justify-between items-center text-sm">
                    <span className="flex items-center gap-1 text-gray-400">
                        <Zap className="w-4 h-4 text-yellow-400" /> Tokens
                    </span>
                    <span className="font-mono text-xs">{quota.tokens_used.toLocaleString()} / {quota.token_limit.toLocaleString()}</span>
                </div>
                <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-gray-700">
                    <div
                        className={`h-full transition-all duration-500 ease-out ${getColor(tokenPct)}`}
                        style={{ width: `${Math.min(tokenPct, 100)}%` }}
                    />
                </div>
            </div>

            <div className="flex flex-col gap-2 mt-2">
                <div className="flex justify-between items-center text-sm">
                    <span className="flex items-center gap-1 text-gray-400">
                        <Banknote className="w-4 h-4 text-green-400" /> Spend
                    </span>
                    <span className="font-mono text-xs">${quota.spend.toFixed(2)} / ${quota.budget.toFixed(2)}</span>
                </div>
                <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-gray-700">
                    <div
                        className={`h-full transition-all duration-500 ease-out ${getColor(spendPct)}`}
                        style={{ width: `${Math.min(spendPct, 100)}%` }}
                    />
                </div>
            </div>

            {(tokenPct >= 95 || spendPct >= 95) && (
                <div className="mt-2 bg-red-900/30 text-red-400 border border-red-800 text-xs px-3 py-2 rounded font-semibold text-center uppercase tracking-wider">
                    Limit Exceeded (Blocked)
                </div>
            )}
        </div>
    );
};

export default QuotaProgress;
