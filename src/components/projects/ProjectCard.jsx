import React, { useState } from 'react';
import { KeyRound, ShieldCheck, Activity, ChevronRight, Eye, EyeOff } from 'lucide-react';

const ProjectCard = ({ project }) => {
    const [showKeyIndex, setShowKeyIndex] = useState(null);

    return (
        <div className="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-md flex flex-col group hover:border-cyan-500 transition-colors">
            <div className="flex justify-between items-start mb-3">
                <h3 className="font-bold text-gray-100 text-lg group-hover:text-cyan-400 transition-colors">{project.name}</h3>
                <span className="bg-cyan-900/40 text-cyan-500 px-2 py-0.5 rounded text-xs font-mono border border-cyan-800">
                    ID: {project.id.substring(0, 8)}
                </span>
            </div>

            <p className="text-gray-400 text-sm mb-6 flex-1 line-clamp-2">{project.description}</p>

            <div className="space-y-4">
                <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1">
                            <KeyRound className="w-3 h-3 text-yellow-500" /> Active API Keys
                        </span>
                        <span className="text-xs bg-gray-800 px-2 rounded-full">{project.api_keys.length}</span>
                    </div>
                    {project.api_keys.map((key, idx) => (
                        <div key={key.id} className="flex justify-between items-center bg-gray-800/50 p-2 rounded mt-2 border border-gray-700/50">
                            <span className="text-xs text-gray-400">{key.name}</span>
                            <div className="flex items-center gap-2">
                                <span className="font-mono text-xs text-gray-300 bg-black/40 px-2 py-1 rounded">
                                    {showKeyIndex === idx ? key.key : "sk-••••••••••••••••••••"}
                                </span>
                                <button
                                    className="text-gray-500 hover:text-white transition-colors"
                                    onClick={() => setShowKeyIndex(showKeyIndex === idx ? null : idx)}
                                >
                                    {showKeyIndex === idx ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>
                    ))}
                </div>

                <div className="flex gap-2">
                    <div className="flex-1 flex items-center justify-center gap-2 bg-gray-900/50 p-2 rounded text-xs text-gray-400 border border-gray-700">
                        <ShieldCheck className="w-4 h-4 text-green-500" /> Sec: Max
                    </div>
                    <div className="flex-1 flex items-center justify-center gap-2 bg-gray-900/50 p-2 rounded text-xs text-gray-400 border border-gray-700">
                        <Activity className="w-4 h-4 text-blue-500" /> 1.2k RQs
                    </div>
                </div>

                <button className="w-full mt-2 flex items-center justify-center gap-2 bg-gray-700 hover:bg-gray-600 text-sm font-semibold py-2 rounded-lg transition-colors">
                    Manage Access <ChevronRight className="w-4 h-4" />
                </button>
            </div>
        </div>
    );
};

export default ProjectCard;
