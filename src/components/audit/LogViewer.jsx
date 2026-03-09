import React from 'react';

const LogViewer = ({ logs, loading }) => {
    if (loading) {
        return <div className="h-full flex items-center justify-center text-gray-500">Loading secure logs...</div>;
    }

    if (logs.length === 0) {
        return <div className="h-full flex items-center justify-center text-gray-500">No logs found matching criteria.</div>;
    }

    return (
        <div className="h-full overflow-y-auto">
            <table className="w-full text-left text-sm text-gray-400">
                <thead className="bg-gray-900/50 text-xs uppercase font-semibold text-gray-300 sticky top-0 backdrop-blur-md">
                    <tr>
                        <th className="px-6 py-4">Timestamp</th>
                        <th className="px-6 py-4">Action</th>
                        <th className="px-6 py-4">Actor</th>
                        <th className="px-6 py-4">Resource</th>
                        <th className="px-6 py-4">Metadata</th>
                    </tr>
                </thead>
                <tbody>
                    {logs.map((log) => (
                        <tr key={log.id} className="border-b border-gray-700 hover:bg-gray-800/50 transition-colors">
                            <td className="px-6 py-4 whitespace-nowrap font-mono text-[10px]">
                                {new Date(log.timestamp).toISOString()}
                            </td>
                            <td className="px-6 py-4 font-mono text-cyan-400">{log.action}</td>
                            <td className="px-6 py-4 font-semibold text-gray-300">{log.actor}</td>
                            <td className="px-6 py-4">{log.resource}</td>
                            <td className="px-6 py-4 font-mono text-[10px] text-gray-500 max-w-xs truncate">
                                {JSON.stringify(log.metadata)}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default LogViewer;
