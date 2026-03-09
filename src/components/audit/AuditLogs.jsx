import React, { useState, useEffect } from 'react';
import LogViewer from './LogViewer';
import LogFilter from './LogFilter';

const AuditLogs = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('');

    useEffect(() => {
        fetch('http://localhost:8000/api/audit_logs/all?limit=100')
            .then(res => res.json())
            .then(data => {
                if (data.logs) setLogs(data.logs);
                setLoading(false);
            })
            .catch(err => {
                console.error("Failed to load audit logs", err);
                setLoading(false);
            });
    }, []);

    const filteredLogs = logs.filter(log =>
        log.action.toLowerCase().includes(filter.toLowerCase()) ||
        log.resource.toLowerCase().includes(filter.toLowerCase()) ||
        log.actor.toLowerCase().includes(filter.toLowerCase())
    );

    return (
        <div className="flex flex-col h-full bg-gray-900 text-white p-6 gap-6 overflow-hidden w-full">
            <div>
                <h1 className="text-2xl font-bold font-mono text-cyan-400 mb-2">SYSTEM AUDIT TRAIL</h1>
                <p className="text-sm text-gray-400">Immutable record of all administrative and system-level actions.</p>
            </div>

            <div className="bg-gray-800 p-4 rounded-xl border border-gray-700 shadow-md">
                <LogFilter filter={filter} setFilter={setFilter} />
            </div>

            <div className="flex-1 overflow-hidden bg-gray-800 rounded-xl border border-gray-700 shadow-md">
                <LogViewer logs={filteredLogs} loading={loading} />
            </div>
        </div>
    );
};

export default AuditLogs;
