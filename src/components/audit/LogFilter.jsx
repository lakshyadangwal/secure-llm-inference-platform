import React from 'react';
import { Search } from 'lucide-react';

const LogFilter = ({ filter, setFilter }) => {
    return (
        <div className="flex items-center bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 focus-within:border-cyan-500 transition-colors w-full md:w-1/2">
            <Search className="text-gray-500 w-5 h-5 mr-3" />
            <input
                type="text"
                placeholder="Filter by action, actor, or resource..."
                className="bg-transparent text-sm text-gray-200 outline-none w-full"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
            />
        </div>
    );
};

export default LogFilter;
