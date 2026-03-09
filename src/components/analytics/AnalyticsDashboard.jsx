import React, { useEffect, useState } from 'react';
import MetricCard from './MetricCard';
import UsageChart from './UsageChart';
import SecurityEventsTable from './SecurityEventsTable';

const AnalyticsDashboard = () => {
    const [summary, setSummary] = useState(null);
    const [events, setEvents] = useState([]);

    useEffect(() => {
        // Fetch summary
        fetch('http://localhost:8000/api/analytics/summary')
            .then(res => res.json())
            .then(data => setSummary(data))
            .catch(err => console.error(err));

        // Fetch security events
        fetch('http://localhost:8000/api/analytics/security-events?limit=10')
            .then(res => res.json())
            .then(data => {
                if (data.events) setEvents(data.events);
            })
            .catch(err => console.error(err));
    }, []);

    return (
        <div className="flex flex-col h-full bg-gray-900 text-white p-6 gap-6 overflow-y-auto w-full">
            <div>
                <h1 className="text-2xl font-bold font-mono text-cyan-400 mb-2">TELEMETRY & ANALYTICS</h1>
                <p className="text-sm text-gray-400">Real-time platform usage and security monitoring.</p>
            </div>

            {/* Top Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard
                    title="Total Requests"
                    value={summary?.total_requests || 0}
                    icon="activity"
                    color="text-blue-400"
                />
                <MetricCard
                    title="Total Tokens"
                    value={summary?.total_tokens || 0}
                    icon="cpu"
                    color="text-purple-400"
                />
                <MetricCard
                    title="Avg Latency"
                    value={`${summary?.avg_latency ? summary.avg_latency.toFixed(1) : 0}ms`}
                    icon="clock"
                    color="text-green-400"
                />
                <MetricCard
                    title="Security Incidents"
                    value={summary?.security_incidents || 0}
                    icon="shield"
                    color="text-red-400"
                />
            </div>

            {/* Charts Area */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                    <UsageChart />
                </div>
                <div className="lg:col-span-1">
                    <SecurityEventsTable events={events} />
                </div>
            </div>
        </div>
    );
};

export default AnalyticsDashboard;
