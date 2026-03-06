import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const STAGES = [
    { id: 'input', label: 'INPUT', sublabel: 'User Prompt', x: 50, y: 120, color: '#6366f1', icon: 'M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z' },
    { id: 'stage1', label: 'STAGE 1', sublabel: 'Rule Engine', x: 210, y: 120, color: '#06b6d4', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4' },
    { id: 'stage2', label: 'STAGE 2', sublabel: 'Groq Classifier', x: 370, y: 120, color: '#8b5cf6', icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' },
    { id: 'stage3', label: 'STAGE 3', sublabel: 'Score Fusion', x: 530, y: 120, color: '#f59e0b', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
    { id: 'result', label: 'RESULT', sublabel: 'Decision', x: 690, y: 120, color: '#10b981', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
];

const CONNECTIONS = [
    { from: 0, to: 1 },
    { from: 1, to: 2 },
    { from: 2, to: 3 },
    { from: 3, to: 4 },
];

const FAST_BLOCK_PATH = { from: 1, to: 4, label: 'FAST BLOCK' };

const Particle = ({ fromX, fromY, toX, toY, color, delay = 0, duration = 0.8 }) => (
    <motion.circle
        r={4}
        fill={color}
        initial={{ cx: fromX, cy: fromY, opacity: 0 }}
        animate={{
            cx: [fromX, toX],
            cy: [fromY, toY],
            opacity: [0, 1, 1, 0],
        }}
        transition={{ duration, delay, ease: 'easeInOut', repeat: Infinity, repeatDelay: 2 }}
        style={{ filter: `drop-shadow(0 0 6px ${color})` }}
    />
);

const AttackFlowVisualizer = ({ isProcessing = false, lastResult = null }) => {
    const [activeStage, setActiveStage] = useState(-1);
    const [fastBlock, setFastBlock] = useState(false);
    const [resultColor, setResultColor] = useState(null);

    useEffect(() => {
        if (!isProcessing) {
            setActiveStage(-1);
            return;
        }
        setFastBlock(false);
        setResultColor(null);
        const timers = [];
        [0, 1, 2, 3, 4].forEach((stage, i) => {
            timers.push(setTimeout(() => setActiveStage(stage), i * 500));
        });
        return () => timers.forEach(clearTimeout);
    }, [isProcessing]);

    useEffect(() => {
        if (lastResult === 'blocked') {
            setResultColor('#ef4444');
            if (Math.random() > 0.5) setFastBlock(true);
        } else if (lastResult === 'flagged') {
            setResultColor('#f59e0b');
        } else if (lastResult === 'allowed') {
            setResultColor('#10b981');
        }
    }, [lastResult]);

    const getStageColor = (index) => {
        if (activeStage < 0) return STAGES[index].color;
        if (index < activeStage) return '#10b981';
        if (index === activeStage) return STAGES[index].color;
        return 'rgba(255,255,255,0.15)';
    };

    const svgWidth = 740;
    const svgHeight = 240;
    const nodeRadius = 32;

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-[var(--card-bg)] backdrop-blur-xl rounded-2xl p-6 border border-[var(--border-primary)] overflow-hidden relative"
        >
            <div className="absolute inset-0 opacity-30"
                style={{
                    backgroundImage: 'radial-gradient(circle, var(--border-primary) 1px, transparent 1px)',
                    backgroundSize: '20px 20px',
                }}
            />
            <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-indigo-500/15 border border-indigo-500/25 flex items-center justify-center">
                            <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                            </svg>
                        </div>
                        <div>
                            <h3 className="text-lg font-bold text-[var(--text-primary)]">Defense Pipeline</h3>
                            <p className="text-xs text-[var(--text-muted)] font-mono">3-stage threat analysis flow</p>
                        </div>
                    </div>
                    <AnimatePresence mode="wait">
                        {isProcessing ? (
                            <motion.div key="processing" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }}
                                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30">
                                <motion.div className="w-2 h-2 rounded-full bg-blue-400"
                                    animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                                    transition={{ duration: 1, repeat: Infinity }} />
                                <span className="text-[10px] font-mono font-bold text-blue-400 tracking-wider">ANALYZING</span>
                            </motion.div>
                        ) : (
                            <motion.div key="idle" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }}
                                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--card-bg)] border border-[var(--border-primary)]">
                                <div className="w-2 h-2 rounded-full bg-emerald-400" />
                                <span className="text-[10px] font-mono font-bold text-[var(--text-muted)] tracking-wider">READY</span>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                <svg viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="w-full h-auto" style={{ minHeight: '160px' }}>
                    <defs>
                        <filter id="glow">
                            <feGaussianBlur stdDeviation="3" result="blur" />
                            <feMerge>
                                <feMergeNode in="blur" />
                                <feMergeNode in="SourceGraphic" />
                            </feMerge>
                        </filter>
                        <linearGradient id="flowGrad" x1="0" y1="0" x2="1" y2="0">
                            <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.2} />
                            <stop offset="50%" stopColor="#06b6d4" stopOpacity={0.8} />
                            <stop offset="100%" stopColor="#06b6d4" stopOpacity={0.2} />
                        </linearGradient>
                    </defs>

                    {CONNECTIONS.map((conn, i) => {
                        const from = STAGES[conn.from];
                        const to = STAGES[conn.to];
                        const active = activeStage > conn.from;
                        return (
                            <g key={`conn-${i}`}>
                                <line
                                    x1={from.x + nodeRadius + 4} y1={from.y}
                                    x2={to.x - nodeRadius - 4} y2={to.y}
                                    stroke="var(--border-primary)" strokeWidth={2} strokeDasharray="6 4" opacity={0.3}
                                />
                                <motion.line
                                    x1={from.x + nodeRadius + 4} y1={from.y}
                                    x2={to.x - nodeRadius - 4} y2={to.y}
                                    stroke={active ? '#10b981' : 'transparent'}
                                    strokeWidth={2}
                                    initial={{ pathLength: 0 }}
                                    animate={{ pathLength: active ? 1 : 0 }}
                                    style={{ filter: active ? 'drop-shadow(0 0 4px #10b98180)' : 'none' }}
                                />
                                {isProcessing && activeStage >= conn.from && (
                                    <Particle
                                        fromX={from.x + nodeRadius + 4} fromY={from.y}
                                        toX={to.x - nodeRadius - 4} toY={to.y}
                                        color="#06b6d4" delay={i * 0.3} duration={0.6}
                                    />
                                )}
                            </g>
                        );
                    })}