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