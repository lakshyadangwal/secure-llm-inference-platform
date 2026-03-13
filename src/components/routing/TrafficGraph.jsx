import React from 'react';

const TrafficGraph = ({ nodes }) => {
    // This is a decorative CSS-based mock of a topology graph
    return (
        <div className="relative w-full h-[300px] flex items-center justify-center bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">

            {/* API Gateway Entry */}
            <div className="absolute left-8 flex flex-col items-center">
                <div className="w-16 h-16 bg-blue-900/50 border border-blue-500 rounded-xl flex items-center justify-center z-10 shadow-[0_0_15px_rgba(59,130,246,0.5)]">
                    <span className="text-xs font-mono text-blue-300 font-bold">API<br />GW</span>
                </div>
            </div>

            {/* Router / Balancer */}
            <div className="absolute left-1/3 flex flex-col items-center">
                <div className="w-14 h-14 bg-purple-900/50 border border-purple-500 rounded-full flex items-center justify-center z-10 shadow-[0_0_15px_rgba(168,85,247,0.5)]">
                    <span className="text-[10px] font-mono text-purple-300">Router</span>
                </div>
            </div>

            {/* Nodes */}
            <div className="absolute right-12 flex flex-col gap-8">
                {nodes.map((n, i) => (
                    <div key={n.id} className="relative flex items-center">
                        <div className={`w-12 h-12 bg-gray-800 border ${n.current_load > 80 ? 'border-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.4)]' : 'border-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.4)]'} rounded z-10 flex items-center justify-center`}>
                            <span className="text-[9px] font-mono text-gray-300">N-{i + 1}</span>
                        </div>
                    </div>
                ))}
            </div>

            {/* Connecting SVG Lines */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-40">
                {/* Gateway to Router */}
                <path d="M 64 150 L 230 150" stroke="#a855f7" strokeWidth="2" strokeDasharray="4 4" fill="none" className="animate-[dash_2s_linear_infinite]" />

                {/* Router to Nodes (Hardcoded approximate positions based on layout) */}
                <path d="M 280 140 Q 400 65 550 65" stroke="#06b6d4" strokeWidth="1" fill="none" />
                <path d="M 285 150 L 550 150" stroke="#f97316" strokeWidth="2" strokeDasharray="4 4" fill="none" className="animate-[dash_1s_linear_infinite]" />
                <path d="M 280 160 Q 400 235 550 235" stroke="#06b6d4" strokeWidth="1" fill="none" />
            </svg>

            <style jsx>{`
                @keyframes dash {
                    to { stroke-dashoffset: -10; }
                }
            `}</style>
        </div>
    );
};

export default TrafficGraph;
