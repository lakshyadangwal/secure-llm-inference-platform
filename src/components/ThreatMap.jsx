import React, { useState, useEffect, useRef, useCallback } from 'react';

const DEMO_DATAPOINTS = [
    { coordinates: [37.6173, 55.7558], intensity: 8, threat: 'Jailbreak', actor: 'APT-29', details: 'Multi-turn jailbreak using "DAN mode" variant. 3 attempts blocked in last hour.', origin: 'Moscow, Russia' },
    { coordinates: [116.4074, 39.9042], intensity: 7, threat: 'Prompt Inject', actor: 'Volt Typhoon', details: 'Adversarial suffix attack targeting Groq classifier bypass. GCG-style payload detected.', origin: 'Beijing, China' },
    { coordinates: [51.3890, 35.6892], intensity: 6, threat: 'Data Exfil', actor: 'OilRig', details: 'Attempted extraction of API keys via roleplay scenario. DLP filter intercepted.', origin: 'Tehran, Iran' },
    { coordinates: [125.7625, 39.0392], intensity: 9, threat: 'APT Probe', actor: 'Lazarus Group', details: 'Systematic probing of defense pipeline. 47 unique payloads in 10 minutes.', origin: 'Pyongyang, DPRK' },
    { coordinates: [-73.9857, 40.7484], intensity: 4, threat: 'Recon Scan', actor: 'Unknown', details: 'Automated scanning for model endpoint enumeration. Rate limited.', origin: 'New York, USA' },
    { coordinates: [-0.1278, 51.5074], intensity: 3, threat: 'Fuzzing', actor: 'CyberVolk', details: 'Low-intensity fuzzing of RAG context window with benign-appearing payloads.', origin: 'London, UK' },
    { coordinates: [2.3522, 48.8566], intensity: 5, threat: 'RAG Poison', actor: 'FIN7', details: 'Document upload containing hidden system prompt overrides in PDF metadata.', origin: 'Paris, France' },
    { coordinates: [77.2090, 28.6139], intensity: 4, threat: 'PII Extract', actor: 'Sidewinder', details: 'Social engineering attempt to extract user PII through conversation manipulation.', origin: 'New Delhi, India' },
    { coordinates: [139.6917, 35.6895], intensity: 3, threat: 'Side Channel', actor: 'Unknown', details: 'Token timing analysis suggesting model architecture fingerprinting.', origin: 'Tokyo, Japan' },
    { coordinates: [-46.6333, -23.5505], intensity: 6, threat: 'DDoS Prompt', actor: 'Anonymous', details: 'Recursive expansion prompts consuming excessive tokens. 45k tokens/request.', origin: 'São Paulo, Brazil' },
    { coordinates: [31.2357, 30.0444], intensity: 5, threat: 'Social Eng', actor: 'DarkHydrus', details: 'Phishing-style prompts requesting internal configuration disclosure.', origin: 'Cairo, Egypt' },
    { coordinates: [28.9784, 41.0082], intensity: 4, threat: 'Token Theft', actor: 'Scattered Spider', details: 'Attempted credential harvesting via crafted conversation flows.', origin: 'Istanbul, Turkey' },
];

const ThreatMap = () => {
    const [dataPoints, setDataPoints] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedThreat, setSelectedThreat] = useState(null);

    // Pan & zoom state
    const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: 1000, h: 500 });
    const [isPanning, setIsPanning] = useState(false);
    const [panStart, setPanStart] = useState({ x: 0, y: 0 });
    const svgRef = useRef(null);

    useEffect(() => {
        fetch(`http://localhost:8000/api/metrics/geodata`)
            .then(res => res.json())
            .then(data => {
                if (data.datapoints && data.datapoints.length > 0) setDataPoints(data.datapoints);
                else setDataPoints(DEMO_DATAPOINTS);
            })
            .catch(() => setDataPoints(DEMO_DATAPOINTS))
            .finally(() => setLoading(false));

        const interval = setInterval(() => {
            setDataPoints(prev => prev.map(p => ({
                ...p,
                intensity: Math.max(1, Math.min(10, p.intensity + (Math.random() > 0.5 ? 1 : -1))),
            })));
        }, 8000);
        return () => clearInterval(interval);
    }, []);

    // Convert lon/lat to SVG coords
    const toSvg = useCallback((lon, lat) => ({
        x: (lon + 180) * (1000 / 360),
        y: ((lat * -1) + 90) * (500 / 180),
    }), []);

    // Mouse → SVG coordinate conversion
    const screenToSvg = useCallback((clientX, clientY) => {
        const svg = svgRef.current;
        if (!svg) return { x: 0, y: 0 };
        const rect = svg.getBoundingClientRect();
        return {
            x: viewBox.x + ((clientX - rect.left) / rect.width) * viewBox.w,
            y: viewBox.y + ((clientY - rect.top) / rect.height) * viewBox.h,
        };
    }, [viewBox]);

    // Zoom with scroll
    const handleWheel = useCallback((e) => {
        e.preventDefault();
        const scaleFactor = e.deltaY > 0 ? 1.15 : 0.87;
        const svgPoint = screenToSvg(e.clientX, e.clientY);

        setViewBox(prev => {
            const newW = Math.max(200, Math.min(2000, prev.w * scaleFactor));
            const newH = Math.max(100, Math.min(1000, prev.h * scaleFactor));
            const newX = svgPoint.x - (svgPoint.x - prev.x) * (newW / prev.w);
            const newY = svgPoint.y - (svgPoint.y - prev.y) * (newH / prev.h);
            return { x: newX, y: newY, w: newW, h: newH };
        });
    }, [screenToSvg]);

    // Pan with mouse drag
    const handleMouseDown = useCallback((e) => {
        if (e.button !== 0) return;
        setIsPanning(true);
        setPanStart({ x: e.clientX, y: e.clientY });
    }, []);

    const handleMouseMove = useCallback((e) => {
        if (!isPanning) return;
        const svg = svgRef.current;
        if (!svg) return;
        const rect = svg.getBoundingClientRect();
        const dx = ((e.clientX - panStart.x) / rect.width) * viewBox.w;
        const dy = ((e.clientY - panStart.y) / rect.height) * viewBox.h;
        setViewBox(prev => ({ ...prev, x: prev.x - dx, y: prev.y - dy }));
        setPanStart({ x: e.clientX, y: e.clientY });
    }, [isPanning, panStart, viewBox]);

    const handleMouseUp = useCallback(() => setIsPanning(false), []);

    // Reset view
    const resetView = () => {
        setViewBox({ x: 0, y: 0, w: 1000, h: 500 });
        setSelectedThreat(null);
    };

    // Zoom to threat
    const focusThreat = (point) => {
        const { x, y } = toSvg(point.coordinates[0], point.coordinates[1]);
        setViewBox({ x: x - 100, y: y - 50, w: 200, h: 100 });
        setSelectedThreat(point);
    };

    const zoomLevel = Math.round((1000 / viewBox.w) * 100);

    return (
        <div className="space-y-0 animate-fade-in relative h-full flex flex-col">
            {/* Top bar */}
            <div className="flex items-center justify-between px-4 py-3 z-10 bg-[#060B12]/80 backdrop-blur-sm border-b border-ns-dark-border">
                <div>
                    <h2 className="text-xl font-orbitron text-ns-blue flex items-center shadow-text-glow">
                        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        Live Threat Topography
                    </h2>
                    <p className="text-gray-500 text-xs mt-0.5">{dataPoints.length} active signals • Scroll to zoom • Drag to pan • Click threats for details</p>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-gray-500 bg-gray-800/60 px-2 py-1 rounded border border-gray-700">{zoomLevel}%</span>
                    <button onClick={resetView} className="text-xs font-mono text-cyan-400 bg-cyan-900/20 px-3 py-1.5 rounded border border-cyan-800 hover:bg-cyan-900/40 transition-colors">
                        RESET VIEW
                    </button>
                </div>
            </div>

            {/* Map area */}
            <div className="flex-1 relative bg-[#060B12] overflow-hidden border border-ns-dark-border shadow-[inset_0_0_100px_rgba(59,130,246,0.1)]" style={{ minHeight: 400 }}>
                {loading ? (
                    <div className="absolute inset-0 flex items-center justify-center">
                        <div className="w-12 h-12 border-4 border-ns-blue border-t-transparent rounded-full animate-spin"></div>
                    </div>
                ) : (
                    <svg
                        ref={svgRef}
                        viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
                        className="w-full h-full"
                        preserveAspectRatio="xMidYMid slice"
                        style={{ cursor: isPanning ? 'grabbing' : 'grab' }}
                        onWheel={handleWheel}
                        onMouseDown={handleMouseDown}
                        onMouseMove={handleMouseMove}
                        onMouseUp={handleMouseUp}
                        onMouseLeave={handleMouseUp}
                    >
                        <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(59, 130, 246, 0.08)" strokeWidth="0.5" />
                        </pattern>
                        <rect x="-500" y="-250" width="2000" height="1000" fill="url(#grid)" />

                        {/* Continents */}
                        <path d="M 150 100 Q 200 80 250 150 T 350 200 T 250 400 T 150 350 Q 100 200 150 100 Z" fill="rgba(30, 58, 138, 0.15)" stroke="rgba(59, 130, 246, 0.3)" strokeWidth="0.8" />
                        <path d="M 500 50 Q 600 20 700 100 T 800 150 T 850 300 T 600 450 Q 550 250 500 50 Z" fill="rgba(30, 58, 138, 0.15)" stroke="rgba(59, 130, 246, 0.3)" strokeWidth="0.8" />
                        <path d="M 850 200 Q 900 150 950 200 T 900 400 T 800 350 Z" fill="rgba(30, 58, 138, 0.15)" stroke="rgba(59, 130, 246, 0.3)" strokeWidth="0.8" />

                        {/* Radar */}
                        <circle cx="500" cy="250" r="400" fill="none" stroke="rgba(59, 130, 246, 0.07)" strokeWidth="1.5" strokeDasharray="10 20">
                            <animateTransform attributeName="transform" type="rotate" from="0 500 250" to="360 500 250" dur="20s" repeatCount="indefinite" />
                        </circle>
                        <circle cx="500" cy="250" r="250" fill="none" stroke="rgba(59, 130, 246, 0.12)" strokeWidth="0.8" />
                        <circle cx="500" cy="250" r="100" fill="none" stroke="rgba(59, 130, 246, 0.2)" strokeWidth="0.8" />
                        <line x1="500" y1="250" x2="900" y2="250" stroke="url(#radarGradient)" strokeWidth="3">
                            <animateTransform attributeName="transform" type="rotate" from="0 500 250" to="360 500 250" dur="4s" repeatCount="indefinite" />
                        </line>

                        <defs>
                            <linearGradient id="radarGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                <stop offset="0%" stopColor="rgba(59, 130, 246, 0.8)" stopOpacity="1" />
                                <stop offset="100%" stopColor="rgba(59, 130, 246, 0)" stopOpacity="0" />
                            </linearGradient>
                            <filter id="glow-red"><feGaussianBlur stdDeviation="3" result="coloredBlur" /><feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
                            <filter id="glow-yellow"><feGaussianBlur stdDeviation="3" result="coloredBlur" /><feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
                            <filter id="glow-selected"><feGaussianBlur stdDeviation="5" result="coloredBlur" /><feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
                        </defs>

                        {/* Attack lines from threats to center */}
                        {dataPoints.map((point, i) => {
                            const { x, y } = toSvg(point.coordinates[0], point.coordinates[1]);
                            if (point.intensity <= 5) return null;
                            return (
                                <line key={`line-${i}`} x1={x} y1={y} x2="500" y2="250" stroke="rgba(239,68,68,0.15)" strokeWidth="0.5" strokeDasharray="4 8">
                                    <animate attributeName="stroke-dashoffset" values="0;12" dur="1.5s" repeatCount="indefinite" />
                                </line>
                            );
                        })}

                        {/* Threat nodes */}
                        {dataPoints.map((point, i) => {
                            const { x, y } = toSvg(point.coordinates[0], point.coordinates[1]);
                            const isHigh = point.intensity > 5;
                            const isSelected = selectedThreat === point;
                            const color = isHigh ? '#ef4444' : '#eab308';
                            const filter = isSelected ? 'url(#glow-selected)' : isHigh ? 'url(#glow-red)' : 'url(#glow-yellow)';
                            const radius = isSelected ? point.intensity * 3.5 : point.intensity * 2;

                            return (
                                <g key={i} style={{ cursor: 'pointer' }} onClick={(e) => { e.stopPropagation(); setSelectedThreat(isSelected ? null : point); }}>
                                    {/* Outer ring on selected */}
                                    {isSelected && (
                                        <circle cx={x} cy={y} r={radius + 8} fill="none" stroke={color} strokeWidth="1.5" strokeDasharray="3 3" opacity="0.6">
                                            <animateTransform attributeName="transform" type="rotate" from={`0 ${x} ${y}`} to={`360 ${x} ${y}`} dur="6s" repeatCount="indefinite" />
                                        </circle>
                                    )}
                                    <circle cx={x} cy={y} r={radius} fill={color} opacity={isSelected ? 0.9 : 0.7} filter={filter}>
                                        <animate attributeName="r" values={`${radius};${radius * 1.6};${radius}`} dur="2.5s" repeatCount="indefinite" />
                                        <animate attributeName="opacity" values={`${isSelected ? 0.9 : 0.7};0.2;${isSelected ? 0.9 : 0.7}`} dur="2.5s" repeatCount="indefinite" />
                                    </circle>
                                    <circle cx={x} cy={y} r="3" fill="#fff" opacity="0.9" />
                                    {/* Label */}
                                    {(isHigh || isSelected) && (
                                        <text x={x + 15} y={y + (isSelected ? -5 : 5)} fill={color} fontSize={isSelected ? "11" : "9"} fontFamily="monospace" fontWeight={isSelected ? "bold" : "normal"} opacity="0.9">
                                            {point.threat.toUpperCase()} [{point.intensity}x]
                                        </text>
                                    )}
                                    {isSelected && point.origin && (
                                        <text x={x + 15} y={y + 8} fill="#94a3b8" fontSize="8" fontFamily="monospace" opacity="0.7">
                                            {point.origin}
                                        </text>
                                    )}
                                </g>
                            );
                        })}
                    </svg>
                )}

                {/* Legend */}
                <div className="absolute bottom-3 right-3 bg-[#0a0f18]/90 p-3 rounded-lg border border-ns-dark-border backdrop-blur-sm">
                    <h4 className="text-[10px] font-orbitron text-gray-400 mb-2 border-b border-gray-800 pb-1.5">Active Signals</h4>
                    <ul className="space-y-1.5 text-[10px] font-mono">
                        <li className="flex items-center text-red-500"><span className="w-2 h-2 rounded-full bg-red-500 mr-2 shadow-[0_0_6px_#ef4444]"></span> Critical (&gt;5)</li>
                        <li className="flex items-center text-yellow-500"><span className="w-2 h-2 rounded-full bg-yellow-500 mr-2 shadow-[0_0_6px_#eab308]"></span> Probe (≤5)</li>
                    </ul>
                </div>

                {/* Threat list sidebar */}
                <div className="absolute top-3 right-3 w-48 bg-[#0a0f18]/90 rounded-lg border border-ns-dark-border backdrop-blur-sm max-h-[280px] overflow-y-auto">
                    <div className="px-3 py-2 border-b border-gray-800 text-[10px] font-orbitron text-gray-400 sticky top-0 bg-[#0a0f18]">THREAT INDEX</div>
                    {dataPoints.sort((a, b) => b.intensity - a.intensity).map((point, i) => {
                        const isHigh = point.intensity > 5;
                        const isSelected = selectedThreat === point;
                        return (
                            <button
                                key={i}
                                onClick={() => focusThreat(point)}
                                className={`w-full text-left px-3 py-1.5 text-[10px] font-mono transition-colors flex items-center gap-2 ${isSelected ? 'bg-blue-900/30 text-white' : 'hover:bg-gray-800/50 text-gray-400'}`}
                            >
                                <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${isHigh ? 'bg-red-500' : 'bg-yellow-500'}`}></span>
                                <span className="truncate">{point.threat}</span>
                                <span className="ml-auto text-gray-600">{point.intensity}x</span>
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* Selected threat detail panel */}
            {selectedThreat && (
                <div className="bg-[#0a0f18] border-t border-ns-dark-border px-4 py-3 flex items-start gap-4 animate-fade-in">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${selectedThreat.intensity > 5 ? 'bg-red-900/30 border border-red-500/40' : 'bg-yellow-900/30 border border-yellow-500/40'}`}>
                        <span className="text-lg">{selectedThreat.intensity > 5 ? '🔴' : '🟡'}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                            <span className="font-orbitron text-sm text-white">{selectedThreat.threat.toUpperCase()}</span>
                            <span className="text-[10px] font-mono text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">Intensity: {selectedThreat.intensity}/10</span>
                            {selectedThreat.actor && <span className="text-[10px] font-mono text-cyan-400 bg-cyan-900/20 px-1.5 py-0.5 rounded border border-cyan-800">{selectedThreat.actor}</span>}
                        </div>
                        <p className="text-xs text-gray-400 leading-relaxed">{selectedThreat.details || 'No additional intelligence available.'}</p>
                        {selectedThreat.origin && <p className="text-[10px] text-gray-500 mt-1 font-mono">📍 {selectedThreat.origin} • [{selectedThreat.coordinates[1].toFixed(2)}°, {selectedThreat.coordinates[0].toFixed(2)}°]</p>}
                    </div>
                    <button onClick={() => setSelectedThreat(null)} className="text-gray-500 hover:text-white transition-colors p-1">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                </div>
            )}
        </div>
    );
};

export default ThreatMap;
