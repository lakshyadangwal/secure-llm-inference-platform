import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

const generateTimeSeriesData = (stats) => {
    const points = 12;
    const data = [];
    const base = Math.max(stats.totalAttempts, 10);
    for (let i = 0; i < points; i++) {
        const t = i / (points - 1);
        const blocked = Math.round(base * (0.3 + 0.6 * t) * (0.8 + Math.random() * 0.4));
        const flagged = Math.round(blocked * (0.1 + Math.random() * 0.15));
        const allowed = Math.round(blocked * (0.03 + Math.random() * 0.07));
        data.push({ time: `${String(i * 2).padStart(2, '0')}:00`, blocked, flagged, allowed });
    }
    return data;
};
const generateHeatmapData = () => {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const data = [];
    days.forEach((day, di) => {
        for (let h = 0; h < 24; h++) {
            const isWorkHours = h >= 8 && h <= 18;
            const isWeekday = di < 5;
            const base = isWorkHours && isWeekday ? 0.6 : isWorkHours ? 0.3 : 0.1;
            data.push({ day, hour: h, value: Math.min(1, base + Math.random() * 0.4) });
        }
    });
    return data;
};
const LineChart = ({ data }) => {
    const [progress, setProgress] = useState(0);
    const [hoveredPoint, setHoveredPoint] = useState(null);
    const width = 600, height = 200, padX = 45, padY = 25;
    const chartW = width - padX * 2, chartH = height - padY * 2;

    useEffect(() => {
        let raf;
        let start = null;
        const animate = (ts) => {
            if (!start) start = ts;
            const p = Math.min(1, (ts - start) / 1200);
            setProgress(p);
            if (p < 1) raf = requestAnimationFrame(animate);
        };
        raf = requestAnimationFrame(animate);
        return () => cancelAnimationFrame(raf);
    }, []);

    const maxVal = Math.max(...data.flatMap(d => [d.blocked, d.flagged, d.allowed]), 1);

    const toPath = (key) => {
        return data.map((d, i) => {
            const x = padX + (i / (data.length - 1)) * chartW;
            const y = padY + chartH - (d[key] / maxVal) * chartH;
            return `${i === 0 ? 'M' : 'L'}${x},${y}`;
        }).join(' ');
    };

    const lines = [
        { key: 'blocked', color: '#10b981', label: 'Blocked' },
        { key: 'flagged', color: '#f59e0b', label: 'Flagged' },
        { key: 'allowed', color: '#ef4444', label: 'Allowed' },
    ];
    return (
        <div className="relative">
            <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto">
                {[0, 0.25, 0.5, 0.75, 1].map((f, i) => {
                    const y = padY + chartH * (1 - f);
                    return (
                        <g key={i}>
                            <line x1={padX} y1={y} x2={width - padX} y2={y} stroke="var(--border-primary)" strokeWidth={0.5} />
                            <text x={padX - 8} y={y + 4} textAnchor="end" fill="var(--text-muted)" fontSize="9" fontFamily="JetBrains Mono">
                                {Math.round(maxVal * f)}
                            </text>
                        </g>
                    );
                })}
                {data.map((d, i) => {
                    if (i % 2 !== 0) return null;
                    const x = padX + (i / (data.length - 1)) * chartW;
                    return (
                        <text key={i} x={x} y={height - 4} textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="JetBrains Mono">
                            {d.time}
                        </text>
                    );
                })}
                <defs>
                    {lines.map(l => (
                        <linearGradient key={l.key} id={`grad-${l.key}`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={l.color} stopOpacity={0.15} />
                            <stop offset="100%" stopColor={l.color} stopOpacity={0} />
                        </linearGradient>
                    ))}
                </defs>
                {lines.map(l => {
                    const linePath = toPath(l.key);
                    const areaPath = `${linePath} L${padX + chartW},${padY + chartH} L${padX},${padY + chartH} Z`;
                    return <path key={`area-${l.key}`} d={areaPath} fill={`url(#grad-${l.key})`} style={{ opacity: progress, transition: 'opacity 0.3s' }} />;
                })}
                {lines.map(l => (
                    <path key={l.key} d={toPath(l.key)} fill="none" stroke={l.color} strokeWidth={2}
                        strokeLinecap="round" strokeLinejoin="round"
                        strokeDasharray={chartW * 3} strokeDashoffset={chartW * 3 * (1 - progress)}
                        style={{ filter: `drop-shadow(0 0 4px ${l.color}40)`, transition: 'stroke-dashoffset 0.05s linear' }}
                    />
                ))}
                {progress > 0.8 && lines.map(l =>
                    data.map((d, i) => {
                        const x = padX + (i / (data.length - 1)) * chartW;
                        const y = padY + chartH - (d[l.key] / maxVal) * chartH;
                        const isHovered = hoveredPoint?.key === l.key && hoveredPoint?.index === i;
                        return (
                            <g key={`${l.key}-${i}`}>
                                <circle cx={x} cy={y} r={isHovered ? 6 : 3} fill={l.color}
                                    style={{ filter: `drop-shadow(0 0 6px ${l.color})`, opacity: Math.min(1, (progress - 0.8) * 5) }} />
                                {isHovered && <circle cx={x} cy={y} r={10} fill={l.color} opacity={0.15} />}
                                <circle cx={x} cy={y} r={12} fill="transparent"
                                    onMouseEnter={() => setHoveredPoint({ key: l.key, index: i, value: d[l.key], x, y })}
                                    onMouseLeave={() => setHoveredPoint(null)} style={{ cursor: 'pointer' }} />
                            </g>
                        );
                    })
                )}
                {hoveredPoint && (
                    <g>
                        <rect x={hoveredPoint.x - 28} y={hoveredPoint.y - 28} width={56} height={18} rx={4}
                            fill="var(--dropdown-bg)" stroke={lines.find(l => l.key === hoveredPoint.key)?.color} strokeWidth={0.5} />
                        <text x={hoveredPoint.x} y={hoveredPoint.y - 16} textAnchor="middle" fill="var(--text-primary)"
                            fontSize="10" fontFamily="JetBrains Mono" fontWeight="bold">{hoveredPoint.value}</text>
                    </g>
                )}
            </svg>
            <div className="flex items-center justify-center gap-6 mt-2">
                {lines.map(l => (
                    <div key={l.key} className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full" style={{ background: l.color, boxShadow: `0 0 8px ${l.color}60` }} />
                        <span className="text-xs font-mono text-[var(--text-muted)]">{l.label}</span>
                    </div>
                ))}
            </div>
        </div>
    );
};
// Heatmap
const Heatmap = ({ data }) => {
    const [hoveredCell, setHoveredCell] = useState(null);
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

    const getColor = (value) => {
        if (value < 0.2) return 'rgba(6,182,212,0.05)';
        if (value < 0.4) return 'rgba(6,182,212,0.15)';
        if (value < 0.6) return 'rgba(6,182,212,0.3)';
        if (value < 0.8) return 'rgba(245,158,11,0.4)';
        return 'rgba(239,68,68,0.5)';
    };

    return (
        <div className="overflow-x-auto">
            <div className="min-w-[500px]">
                {/* Hour labels */}
                <div className="flex ml-10 mb-1">
                    {Array.from({ length: 24 }, (_, h) => (
                        <div key={h} className="flex-1 text-center text-[8px] font-mono text-[var(--text-muted)]">
                            {h % 4 === 0 ? `${String(h).padStart(2, '00')}` : ''}
                        </div>
                    ))}
                </div>

                {/* Grid */}
                {days.map((day, di) => (
                    <div key={day} className="flex items-center gap-1 mb-1">
                        <span className="w-9 text-right text-[9px] font-mono text-[var(--text-muted)] flex-shrink-0">{day}</span>
                        <div className="flex flex-1 gap-[2px]">
                            {Array.from({ length: 24 }, (_, h) => {
                                const cell = data.find(c => c.day === day && c.hour === h);
                                const val = cell?.value || 0;
                                const isHovered = hoveredCell?.day === day && hoveredCell?.hour === h;
                                return (
                                    <motion.div
                                        key={h}
                                        initial={{ opacity: 0, scale: 0 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        transition={{ delay: (di * 24 + h) * 0.003, duration: 0.2 }}
                                        className="flex-1 aspect-square rounded-sm cursor-pointer transition-all"
                                        style={{
                                            background: getColor(val),
                                            border: isHovered ? '1px solid rgba(6,182,212,0.5)' : '1px solid transparent',
                                            boxShadow: isHovered ? `0 0 8px ${getColor(val)}` : 'none',
                                            transform: isHovered ? 'scale(1.4)' : 'scale(1)',
                                        }}
                                        onMouseEnter={() => setHoveredCell({ day, hour: h, value: val })}
                                        onMouseLeave={() => setHoveredCell(null)}
                                    />
                                );
                            })}
                        </div>
                    </div>
                ))}

                {/* Heatmap tooltip */}
                {hoveredCell && (
                    <div className="mt-2 text-center text-xs font-mono text-[var(--text-muted)]">
                        <span className="text-[var(--text-primary)] font-bold">{hoveredCell.day} {String(hoveredCell.hour).padStart(2, '0')}:00</span>
                        {' — '}Intensity: <span className="font-bold" style={{ color: hoveredCell.value > 0.6 ? '#f59e0b' : '#06b6d4' }}>
                            {Math.round(hoveredCell.value * 100)}%
                        </span>
                    </div>
                )}

                {/* Scale */}
                <div className="flex items-center justify-end gap-1 mt-3">
                    <span className="text-[8px] font-mono text-[var(--text-muted)]">Low</span>
                    {[0.1, 0.3, 0.5, 0.7, 0.9].map(v => (
                        <div key={v} className="w-3 h-3 rounded-sm" style={{ background: getColor(v) }} />
                    ))}
                    <span className="text-[8px] font-mono text-[var(--text-muted)]">High</span>
                </div>
            </div>
        </div>
    );
};
// Main Component
const ThreatAnalytics = ({ stats }) => {
    const [timeSeriesData] = useState(() => generateTimeSeriesData(stats));
    const [heatmapData] = useState(() => generateHeatmapData());

    const containerVariants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: { staggerChildren: 0.15 },
        },
    };

    const cardVariants = {
        hidden: { opacity: 0, y: 30, scale: 0.97 },
        visible: {
            opacity: 1, y: 0, scale: 1,
            transition: { type: 'spring', stiffness: 300, damping: 25 },
        },
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="h-full overflow-y-auto scrollbar-hide"
        >
            <div className="p-8">
                {/* Header */}
                <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
                    <h2 className="text-3xl font-bold bg-gradient-to-r from-[var(--text-primary)] via-cyan-400 to-purple-400 bg-clip-text text-transparent mb-2">
                        Threat Analytics
                    </h2>
                    <p className="text-sm text-[var(--text-muted)] font-mono tracking-wide">
                        Real-time attack pattern analysis and threat intelligence
                    </p>
                </motion.div>

                <motion.div variants={containerVariants} initial="hidden" animate="visible" className="space-y-6">
                    {/* Line Chart card */}
                    <motion.div variants={cardVariants}
                        className="bg-[var(--card-bg)] backdrop-blur-xl rounded-2xl p-6 border border-[var(--border-primary)] hover:border-[var(--border-hover)] transition-all"
                    >
                        <div className="flex items-center justify-between mb-6">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/25 flex items-center justify-center">
                                    <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
                                    </svg>
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-[var(--text-primary)]">Attack Timeline</h3>
                                    <p className="text-xs text-[var(--text-muted)] font-mono">Last 24 hours activity</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                <span className="text-[10px] font-mono font-bold text-emerald-400 tracking-wider">LIVE</span>
                            </div>
                        </div>
                        <LineChart data={timeSeriesData} />
                    </motion.div>

                    {/* Donut + Heatmap grid */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <motion.div variants={cardVariants}
                            className="bg-[var(--card-bg)] backdrop-blur-xl rounded-2xl p-6 border border-[var(--border-primary)] hover:border-[var(--border-hover)] transition-all"
                        >
                            <div className="flex items-center gap-3 mb-6">
                                <div className="w-10 h-10 rounded-xl bg-purple-500/15 border border-purple-500/25 flex items-center justify-center">
                                    <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" />
                                    </svg>
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-[var(--text-primary)]">Attack Distribution</h3>
                                    <p className="text-xs text-[var(--text-muted)] font-mono">By category</p>
                                </div>
                            </div>
                            <DonutChart stats={stats} />
                        </motion.div>

                        <motion.div variants={cardVariants}
                            className="bg-[var(--card-bg)] backdrop-blur-xl rounded-2xl p-6 border border-[var(--border-primary)] hover:border-[var(--border-hover)] transition-all"
                        >
                            <div className="flex items-center gap-3 mb-6">
                                <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/25 flex items-center justify-center">
                                    <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z" />
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z" />
                                    </svg>
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-[var(--text-primary)]">Activity Heatmap</h3>
                                    <p className="text-xs text-[var(--text-muted)] font-mono">Attack intensity by day & hour</p>
                                </div>
                            </div>
                            <Heatmap data={heatmapData} />
                        </motion.div>
                    </div>
                </motion.div>
            </div>
        </motion.div>
    );
};

export default ThreatAnalytics;