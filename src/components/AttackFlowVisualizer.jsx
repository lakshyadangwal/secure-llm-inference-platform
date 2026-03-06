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