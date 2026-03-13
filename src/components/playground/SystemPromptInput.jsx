import React from 'react';
import { Settings } from 'lucide-react';

const SystemPromptInput = ({ systemPrompt, setSystemPrompt }) => {
    return (
        <div className="flex flex-col h-full">
            <div className="flex items-center gap-2 mb-3">
                <Settings className="text-cyan-400 w-5 h-5" />
                <h3 className="font-semibold text-gray-200">System Directives</h3>
            </div>

            <p className="text-xs text-gray-500 mb-4 font-light">
                Define the core behavior and ethical boundaries of the assistant.
            </p>

            <textarea
                className="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm text-gray-300 focus:outline-none focus:border-cyan-500 resize-none flex-1 transition-colors"
                placeholder="Enter the initial system prompt..."
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
            />
        </div>
    );
};

export default SystemPromptInput;
