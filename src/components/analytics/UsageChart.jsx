import React, { useEffect, useState } from 'react';
// Simple CSS bar chart with demo data fallback

const DEMO_DATA = Array.from({ length: 24 }, (_, i) => ({
    timestamp: new Date(Date.now() - (23 - i) * 3600000).toISOString(),
    value: Math.floor(Math.random() * 400 + 100 + (i > 8 && i < 20 ? 300 : 0)),
}));

const UsageChart = () => {
    const [data, setData] = useState(DEMO_DATA);

    useEffect(() => {
        fetch('http://localhost:8000/api/analytics/timeseries/usage?hours=24')
            .then(res => res.json())
            .then(resData => { if (resData.data && resData.data.length > 0) setData(resData.data); })
            .catch(() => { });
    }, []);

    const maxVal = Math.max(...data.map(d => d.value), 1);

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-md h-full flex flex-col">
            <h3 className="font-semibold text-gray-200 mb-6">Inference Volume (24h)</h3>

            <div className="flex-1 flex items-end gap-2 px-2 pt-10 border-b border-l border-gray-600 relative min-h-[250px]">
                <div className="absolute top-0 left-[-10px] text-xs text-gray-500 font-mono">{maxVal}</div>
                <div className="absolute bottom-0 left-[-10px] text-xs text-gray-500 font-mono translate-y-full">0</div>

                {data.map((point, idx) => {
                    const heightPct = (point.value / maxVal) * 100;
                    const timeStr = new Date(point.timestamp).getHours() + "h";

                    return (
                        <div key={idx} className="flex-1 flex flex-col items-center justify-end group">
                            <div
                                className="w-full bg-cyan-500/80 hover:bg-cyan-400 rounded-t-sm transition-all duration-300 relative"
                                style={{ height: `${heightPct}%`, minHeight: '4px' }}
                            >
                                <div className="opacity-0 group-hover:opacity-100 absolute -top-8 left-1/2 -translate-x-1/2 bg-gray-900 border border-gray-600 text-xs px-2 py-1 rounded transition-opacity whitespace-nowrap z-10">
                                    {point.value} reqs
                                </div>
                            </div>
                            <span className="text-[10px] text-gray-500 mt-2 truncate max-w-full hidden md:block">
                                {idx % 4 === 0 ? timeStr : ''}
                            </span>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

export default UsageChart;
