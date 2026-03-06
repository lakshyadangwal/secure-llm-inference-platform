import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const ThreatMap = () => {
    const [dataPoints, setDataPoints] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchGeoData();
        const interval = setInterval(fetchGeoData, 10000); // refresh every 10s
        return () => clearInterval(interval);
    }, []);

    const fetchGeoData = async () => {
        try {
            const response = await fetch(`${api.baseURL}/api/metrics/geodata`);
            const data = await response.json();
            setDataPoints(data.datapoints || []);
        } catch (error) {
            console.error("Failed to fetch geodata", error);
        } finally {
            setLoading(false);
        }
    };

    // A simple SVG map rendering for pure visual effect without heavy dependencies
    return (
        <div className="space-y-6 animate-fade-in relative">
            <div className="absolute top-4 left-4 z-10">
                <h2 className="text-2xl font-orbitron text-ns-blue flex items-center shadow-text-glow">
                    <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    Live Threat Topography
                </h2>
                <p className="text-gray-400 text-sm mt-1">Real-time vector origins mapping.</p>
            </div>

            <div className="glass-panel p-0 overflow-hidden h-[600px] relative bg-[#060B12] flex items-center justify-center border border-ns-dark-border shadow-[inset_0_0_100px_rgba(59,130,246,0.1)]">

                {loading ? (
                    <div className="absolute inset-0 flex items-center justify-center">
                        <div className="w-12 h-12 border-4 border-ns-blue border-t-transparent rounded-full animate-spin"></div>
                    </div>
                ) : (
                    <svg viewBox="0 0 1000 500" className="w-full h-full opacity-80" preserveAspectRatio="xMidYMid slice">
                        {/* Grid lines */}
                        <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(59, 130, 246, 0.1)" strokeWidth="1" />
                        </pattern>
                        <rect width="100%" height="100%" fill="url(#grid)" />

                        {/* Abstract continents shape (very simplified SVG paths for effect) */}
                        <path d="M 150 100 Q 200 80 250 150 T 350 200 T 250 400 T 150 350 Q 100 200 150 100 Z" fill="rgba(30, 58, 138, 0.2)" stroke="rgba(59, 130, 246, 0.4)" strokeWidth="1" />
                        <path d="M 500 50 Q 600 20 700 100 T 800 150 T 850 300 T 600 450 Q 550 250 500 50 Z" fill="rgba(30, 58, 138, 0.2)" stroke="rgba(59, 130, 246, 0.4)" strokeWidth="1" />
                        <path d="M 850 200 Q 900 150 950 200 T 900 400 T 800 350 Z" fill="rgba(30, 58, 138, 0.2)" stroke="rgba(59, 130, 246, 0.4)" strokeWidth="1" />

                        {/* Radar scanning effect */}
                        <circle cx="500" cy="250" r="400" fill="none" stroke="rgba(59, 130, 246, 0.1)" strokeWidth="2" strokeDasharray="10 20">
                            <animateTransform attributeName="transform" type="rotate" from="0 500 250" to="360 500 250" dur="20s" repeatCount="indefinite" />
                        </circle>
                        <circle cx="500" cy="250" r="250" fill="none" stroke="rgba(59, 130, 246, 0.2)" strokeWidth="1" />
                        <circle cx="500" cy="250" r="100" fill="none" stroke="rgba(59, 130, 246, 0.3)" strokeWidth="1" />
                        <line x1="500" y1="250" x2="900" y2="250" stroke="url(#radarGradient)" strokeWidth="4">
                            <animateTransform attributeName="transform" type="rotate" from="0 500 250" to="360 500 250" dur="4s" repeatCount="indefinite" />
                        </line>

                        <defs>
                            <linearGradient id="radarGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                                <stop offset="0%" stopColor="rgba(59, 130, 246, 0.8)" stopOpacity="1" />
                                <stop offset="100%" stopColor="rgba(59, 130, 246, 0)" stopOpacity="0" />
                            </linearGradient>

                            {/* Threat Glow Effects */}
                            <filter id="glow-red">
                                <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                                <feMerge>
                                    <feMergeNode in="coloredBlur" />
                                    <feMergeNode in="SourceGraphic" />
                                </feMerge>
                            </filter>
                            <filter id="glow-yellow">
                                <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                                <feMerge>
                                    <feMergeNode in="coloredBlur" />
                                    <feMergeNode in="SourceGraphic" />
                                </feMerge>
                            </filter>
                        </defs>

                        {/* Rendering mapped threats */}
                        {dataPoints.map((point, i) => {
                            // Convert lon/lat roughly to SVG coordinates (for visualization only)
                            const [lon, lat] = point.coordinates;
                            const x = (lon + 180) * (1000 / 360);
                            const y = ((lat * -1) + 90) * (500 / 180);

                            const isHighSeverity = point.intensity > 5;
                            const color = isHighSeverity ? '#ef4444' : '#eab308';
                            const filter = isHighSeverity ? 'url(#glow-red)' : 'url(#glow-yellow)';

                            return (
                                <g key={i}>
                                    <circle
                                        cx={x}
                                        cy={y}
                                        r={point.intensity * 2}
                                        fill={color}
                                        opacity="0.8"
                                        filter={filter}
                                    >
                                        <animate attributeName="r" values={`${point.intensity * 2};${point.intensity * 4};${point.intensity * 2}`} dur="2s" repeatCount="indefinite" />
                                        <animate attributeName="opacity" values="0.8;0.2;0.8" dur="2s" repeatCount="indefinite" />
                                    </circle>
                                    <circle cx={x} cy={y} r="2" fill="#fff" />
                                    {isHighSeverity && (
                                        <text x={x + 15} y={y + 5} fill="#ef4444" fontSize="10" fontFamily="monospace" opacity="0.8">
                                            {point.threat.toUpperCase()} [{point.intensity}x]
                                        </text>
                                    )}
                                </g>
                            );
                        })}
                    </svg>
                )}

                {/* Active Threat Legend */}
                <div className="absolute bottom-4 right-4 bg-[#0a0f18]/80 p-4 rounded-lg border border-ns-dark-border backdrop-blur-sm">
                    <h4 className="text-xs font-orbitron text-gray-400 mb-3 border-b border-gray-800 pb-2">Active Signals</h4>
                    <ul className="space-y-2 text-xs font-mono">
                        <li className="flex items-center text-red-500"><span className="w-2 h-2 rounded-full bg-red-500 mr-2 shadow-[0_0_8px_#ef4444]"></span> Critical Injection (Severity &gt; 5)</li>
                        <li className="flex items-center text-yellow-500"><span className="w-2 h-2 rounded-full bg-yellow-500 mr-2 shadow-[0_0_8px_#eab308]"></span> Probe / Exploration (Severity {'<='} 5)</li>
                    </ul>
                </div>
            </div>
        </div>
    );
};

export default ThreatMap;
