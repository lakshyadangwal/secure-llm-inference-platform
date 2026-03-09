import React, { useEffect, useState } from 'react';
// We'll use a simple CSS-based visualization to avoid requiring D3/Recharts 
// if they aren't installed, keeping the implementation lightweight for this iteration.

const UsageChart = () => {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch('http://localhost:8000/api/analytics/timeseries/usage?hours=24')
            .then(res => res.json())
            .then(resData => {
                if (resData.data) setData(resData.data);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    }, []);

    // Calculate max value for scaling
    const maxVal = Math.max(...data.map(d => d.value), 1);

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-md h-full flex flex-col">
            <h3 className="font-semibold text-gray-200 mb-6">Inference Volume (24h)</h3>

            {loading ? (
                <div className="flex-1 flex items-center justify-center text-gray-500">Loading metrics...</div>
            ) : data.length === 0 ? (
                <div className="flex-1 flex items-center justify-center text-gray-500">No data available</div>
            ) : (
                <div className="flex-1 flex items-end gap-2 px-2 pt-10 border-b border-l border-gray-600 relative min-h-[250px]">
                    {/* Y-Axis Label */}
                    <div className="absolute top-0 left-[-10px] text-xs text-gray-500 font-mono">
                        {maxVal}
                    </div>
                    <div className="absolute bottom-0 left-[-10px] text-xs text-gray-500 font-mono translate-y-full">
                        0
                    </div>

                    {/* Bars */}
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
                        )
                    })}
                </div>
            )}
        </div>
    );
};

export default UsageChart;
