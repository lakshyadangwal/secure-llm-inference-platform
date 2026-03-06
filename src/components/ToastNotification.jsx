import React, { createContext, useContext, useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const ToastContext = createContext(null);

const TOAST_ICONS = {
    success: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
    ),
    error: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
    ),
    warning: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
    ),
    info: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
    ),
};
const TOAST_STYLES = {
    success: {
        border: 'rgba(16,185,129,0.4)',
        bg: 'rgba(16,185,129,0.08)',
        icon: '#10b981',
        glow: 'rgba(16,185,129,0.15)',
        progress: 'linear-gradient(90deg, #10b981, #34d399)',
    },
    error: {
        border: 'rgba(239,68,68,0.4)',
        bg: 'rgba(239,68,68,0.08)',
        icon: '#ef4444',
        glow: 'rgba(239,68,68,0.15)',
        progress: 'linear-gradient(90deg, #ef4444, #f87171)',
    },
    warning: {
        border: 'rgba(245,158,11,0.4)',
        bg: 'rgba(245,158,11,0.08)',
        icon: '#f59e0b',
        glow: 'rgba(245,158,11,0.15)',
        progress: 'linear-gradient(90deg, #f59e0b, #fbbf24)',
    },
    info: {
        border: 'rgba(6,182,212,0.4)',
        bg: 'rgba(6,182,212,0.08)',
        icon: '#06b6d4',
        glow: 'rgba(6,182,212,0.15)',
        progress: 'linear-gradient(90deg, #06b6d4, #22d3ee)',
    },
};

let toastIdCounter = 0;