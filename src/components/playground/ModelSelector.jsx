import React from 'react';

const ModelSelector = ({ model, setModel, temperature, setTemperature }) => {
    return (
        <div className="flex flex-col gap-4">
            <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Model</label>
                <select
                    className="w-full bg-gray-900 border border-gray-700 text-white rounded-lg p-2.5 outline-none focus:border-cyan-500 transition-colors"
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                >
                    <option value="llama3.1:latest">Llama 3.1 (8B)</option>
                    <option value="llama2:latest">Llama 2 (7B)</option>
                    <option value="mistral:latest">Mistral (7B)</option>
                    <option value="phi:latest">Microsoft Phi-2</option>
                </select>
            </div>

            <div>
                <div className="flex justify-between items-center mb-2">
                    <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Temperature</label>
                    <span className="bg-gray-900 px-2 py-1 rounded text-xs text-cyan-400 font-mono">{temperature}</span>
                </div>
                <input
                    type="range"
                    min="0.0"
                    max="1.0"
                    step="0.1"
                    value={temperature}
                    onChange={(e) => setTemperature(parseFloat(e.target.value))}
                    className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                />
                <div className="flex justify-between text-[10px] text-gray-500 mt-1">
                    <span>Precise</span>
                    <span>Creative</span>
                </div>
            </div>
        </div>
    );
};

export default ModelSelector;
