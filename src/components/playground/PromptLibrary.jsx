import React, { useEffect, useState } from 'react';
import PromptCard from './PromptCard';
import { BookOpen } from 'lucide-react';

const PromptLibrary = ({ onLoadPrompt }) => {
    const [prompts, setPrompts] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Fetch mock library from backend
        fetch('http://localhost:8000/api/playground/prompts')
            .then(res => res.json())
            .then(data => {
                if (data.prompts) setPrompts(data.prompts);
                setLoading(false);
            })
            .catch(err => {
                console.error("Failed to load prompts:", err);
                setLoading(false);
            });
    }, []);

    return (
        <div className="flex flex-col h-full">
            <div className="flex items-center gap-2 mb-3 sticky top-0 bg-gray-800 pb-2 z-10 border-b border-gray-700">
                <BookOpen className="text-blue-400 w-5 h-5" />
                <h3 className="font-semibold text-gray-200">Prompt Library</h3>
            </div>

            <div className="flex flex-col gap-3 mt-2 pr-1 h-full overflow-y-auto custom-scrollbar">
                {loading ? (
                    <div className="text-xs text-center text-gray-500 py-4">Loading library...</div>
                ) : prompts.length === 0 ? (
                    <div className="text-xs text-center text-gray-500 py-4">No prompts available.</div>
                ) : (
                    prompts.map(prompt => (
                        <PromptCard
                            key={prompt.id}
                            prompt={prompt}
                            onLoad={() => onLoadPrompt(prompt)}
                        />
                    ))
                )}
            </div>
        </div>
    );
};

export default PromptLibrary;
