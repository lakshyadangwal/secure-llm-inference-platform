import React from 'react';
import { Play } from 'lucide-react';

const PromptCard = ({ prompt, onLoad }) => {
    return (
        <div className="bg-gray-900 border border-gray-700 hover:border-cyan-500 hover:bg-gray-800 transition-all rounded-lg p-3 cursor-pointer group">
            <div className="flex justify-between items-start mb-2">
                <h4 className="text-sm font-semibold text-gray-200 group-hover:text-cyan-400 transition-colors">{prompt.name}</h4>
                <span className="text-[10px] bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full uppercase tracking-wider">{prompt.category}</span>
            </div>
            <p className="text-xs text-gray-400 mb-3 line-clamp-2 leading-relaxed">
                {prompt.description}
            </p>

            <div className="flex justify-between items-center mt-2 border-t border-gray-700/50 pt-2">
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        onLoad();
                    }}
                    className="flex items-center gap-1 text-xs text-cyan-500 hover:text-cyan-400 font-semibold"
                >
                    <Play className="w-3 h-3" /> Load
                </button>
            </div>
        </div>
    );
};

export default PromptCard;
