import React, { useState, useRef } from 'react';

// Client-side injection detection patterns
const INJECTION_PATTERNS = [
    { name: 'System Prompt Override', pattern: /\b(ignore|disregard|forget)\b.*\b(previous|prior|above|all)\b.*\b(instructions?|rules?|guidelines?|prompt)\b/i },
    { name: 'Role Manipulation', pattern: /\b(you are now|act as|pretend|roleplay|from now on)\b/i },
    { name: 'Hidden Instruction', pattern: /\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|<\/?system>|<\/?instruction>/i },
    { name: 'DAN / Jailbreak', pattern: /\bDAN\b|do anything now|bypass.*(?:rules|safety|filter)|jailbreak/i },
    { name: 'Data Exfiltration', pattern: /(?:output|reveal|show|print|display).*(?:system prompt|api key|password|secret|config)/i },
    { name: 'Encoded Payload', pattern: /[A-Za-z0-9+/]{40,}={0,2}/i },
    { name: 'Markdown/HTML Injection', pattern: /<script|<iframe|javascript:|onerror=|onload=/i },
    { name: 'Indirect Prompt Injection', pattern: /(?:new instructions?|updated guidelines?|revised rules?).*(?:ignore|override|replace)/i },
];

const RagScanner = () => {
    const [file, setFile] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);

    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];
        if (selectedFile) {
            setFile(selectedFile);
            setResults(null);
            setError(null);
        }
    };

    const handleDragOver = (e) => { e.preventDefault(); e.stopPropagation(); };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            setFile(e.dataTransfer.files[0]);
            setResults(null);
            setError(null);
        }
    };

    const startScan = async () => {
        if (!file) return;
        setIsScanning(true);
        setError(null);
        setResults(null);

        try {
            const text = await file.text();

            // Simulate processing delay
            await new Promise(r => setTimeout(r, 1500));

            // Chunk the document (~500 chars per chunk)
            const chunkSize = 500;
            const chunks = [];
            for (let i = 0; i < text.length; i += chunkSize) {
                chunks.push(text.slice(i, i + chunkSize));
            }

            // Scan each chunk against patterns
            let totalThreats = 0;
            const chunkResults = chunks.map((chunk, idx) => {
                let isThreat = false;
                let matchedRule = null;

                for (const pattern of INJECTION_PATTERNS) {
                    if (pattern.pattern.test(chunk)) {
                        isThreat = true;
                        matchedRule = pattern.name;
                        totalThreats++;
                        break;
                    }
                }

                return {
                    chunk_id: idx + 1,
                    is_threat: isThreat,
                    matched_rule: matchedRule,
                    text_preview: chunk.substring(0, 120) + (chunk.length > 120 ? '...' : ''),
                };
            });

            setResults({
                is_poisoned: totalThreats > 0,
                total_chunks: chunks.length,
                total_threats_found: totalThreats,
                chunk_results: chunkResults,
            });
        } catch (e) {
            setError(`Failed to scan document: ${e.message}`);
        } finally {
            setIsScanning(false);
        }
    };

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Upload */}
                <div className="glass-panel p-6 shadow-glow">
                    <h2 className="text-xl font-orbitron text-ns-blue mb-4 flex items-center">
                        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                        RAG Context Poisoning Defense
                    </h2>
                    <p className="text-gray-400 text-sm mb-6 leading-relaxed">
                        Upload text documents destined for RAG. The system chunks and scans for hidden instructions, prompt injections, or adversarial payloads. <span className="text-emerald-400 font-mono text-xs">Client-side analysis — no backend needed.</span>
                    </p>

                    <div
                        className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${file ? 'border-indigo-500 bg-indigo-900/10' : 'border-ns-dark-border hover:border-gray-500 bg-ns-darker'}`}
                        onClick={() => fileInputRef.current?.click()}
                        onDragOver={handleDragOver}
                        onDrop={handleDrop}
                    >
                        <input type="file" ref={fileInputRef} onChange={handleFileChange} style={{ display: 'none' }} accept=".txt,.md,.csv,.json" />
                        <svg className={`w-12 h-12 mx-auto mb-4 ${file ? 'text-indigo-400' : 'text-gray-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>

                        {file ? (
                            <div>
                                <p className="text-indigo-400 font-bold">{file.name}</p>
                                <p className="text-xs text-gray-500 mt-1">{(file.size / 1024).toFixed(2)} KB</p>
                            </div>
                        ) : (
                            <div>
                                <p className="text-gray-300">Click to upload or drag and drop</p>
                                <p className="text-xs text-gray-500 mt-1">.TXT, .MD, .CSV, .JSON support</p>
                            </div>
                        )}
                    </div>

                    <button
                        onClick={startScan}
                        disabled={!file || isScanning}
                        className={`mt-6 w-full py-3 rounded-md font-bold transition-all ${!file || isScanning ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-gradient-to-r from-indigo-600 to-ns-blue hover:from-indigo-500 hover:to-blue-400 text-white shadow-[0_0_15px_rgba(59,130,246,0.5)]'}`}
                    >
                        {isScanning ? (
                            <span className="flex items-center justify-center">
                                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                                Scanning Document Chunks...
                            </span>
                        ) : 'INITIATE SECURITY SCAN'}
                    </button>

                    {error && (
                        <div className="mt-4 p-3 bg-red-900/20 border border-red-500/50 rounded text-red-400 text-sm flex items-center">
                            <svg className="w-5 h-5 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd"></path></svg>
                            {error}
                        </div>
                    )}
                </div>

                {/* Results */}
                <div className="glass-panel p-6 shadow-glow bg-[#0a0f18]">
                    <h3 className="text-lg font-orbitron text-gray-300 mb-4 border-b border-ns-dark-border pb-2">Analysis Report</h3>

                    {!results && !isScanning && (
                        <div className="h-48 flex items-center justify-center text-gray-600 italic">Awaiting document ingestion...</div>
                    )}

                    {isScanning && (
                        <div className="h-64 flex flex-col items-center justify-center space-y-4">
                            <div className="w-full max-w-xs h-2 bg-gray-800 rounded-full overflow-hidden">
                                <div className="h-full bg-indigo-500 w-1/2 animate-pulse"></div>
                            </div>
                            <p className="text-sm font-mono text-indigo-400 animate-pulse">Running Neural Pattern Analysis...</p>
                        </div>
                    )}

                    {results && (
                        <div className="space-y-6 animate-fade-in">
                            <div className={`p-4 rounded-lg flex items-center justify-between ${results.is_poisoned ? 'bg-red-900/20 border border-red-500/50' : 'bg-green-900/20 border border-green-500/50'}`}>
                                <div>
                                    <h4 className={`font-bold ${results.is_poisoned ? 'text-red-400' : 'text-green-400'}`}>
                                        {results.is_poisoned ? '⚠️ DOCUMENT POISONED' : '✅ DOCUMENT SECURE'}
                                    </h4>
                                    <p className="text-sm text-gray-400 mt-1">Processed {results.total_chunks} chunks</p>
                                </div>
                                <div className={`text-4xl font-orbitron ${results.is_poisoned ? 'text-red-500 shadow-text-glow' : 'text-green-500 text-shadow-glow'}`}>
                                    {results.total_threats_found} Threats
                                </div>
                            </div>

                            <div className="space-y-3 max-h-[300px] overflow-y-auto pr-2">
                                <h4 className="text-xs uppercase tracking-widest text-gray-500 mb-2">Chunk Level Details</h4>
                                {results.chunk_results.map(chunk => (
                                    <div key={chunk.chunk_id} className={`p-3 rounded border ${chunk.is_threat ? 'bg-red-900/10 border-red-500/30' : 'bg-gray-800/30 border-gray-700'}`}>
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="text-xs font-mono text-gray-400">Chunk {String(chunk.chunk_id).padStart(3, '0')}</span>
                                            {chunk.is_threat ? (
                                                <span className="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 rounded border border-red-500/50">MATCH: {chunk.matched_rule}</span>
                                            ) : (
                                                <span className="text-xs text-green-500/50">CLEAR</span>
                                            )}
                                        </div>
                                        <p className="text-xs text-gray-300 font-mono opacity-80 pl-2 border-l-2 border-gray-600">{chunk.text_preview}</p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default RagScanner;
