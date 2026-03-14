import React, { createContext, useContext, useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// ─── Context ──────────────────────────────────────────────────────────────────
const ToastContext = createContext(null);

// ─── Icons (SVG) ──────────────────────────────────────────────────────────────
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

// ─── Per-type visual styles ───────────────────────────────────────────────────
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

// ─── Default duration in ms ───────────────────────────────────────────────────
const DEFAULT_DURATION = 4000;

// ─── useToast hook ────────────────────────────────────────────────────────────
/**
 * Returns toast convenience methods from the nearest ToastProvider.
 *
 * @example
 *   const toast = useToast();
 *   toast.success('Saved!');
 *   toast.error('Something broke');
 *   toast.warning('Rate limited');
 *   toast.info('Scanning…');
 *   toast('Custom message', { type: 'info', duration: 6000 });
 */
export function useToast() {
    const ctx = useContext(ToastContext);
    if (!ctx) {
        throw new Error('useToast must be used within a <ToastProvider>');
    }
    return ctx;
}

// ─── ToastProvider ────────────────────────────────────────────────────────────
/**
 * Wrap your app (or a subtree) with <ToastProvider> to enable useToast().
 *
 * @example
 *   <ToastProvider>
 *     <App />
 *   </ToastProvider>
 */
export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([]);
    const timersRef = useRef({});

    // Remove a toast by id and clear its auto-dismiss timer
    const removeToast = useCallback((id) => {
        clearTimeout(timersRef.current[id]);
        delete timersRef.current[id];
        setToasts((prev) => prev.filter((t) => t.id !== id));
    }, []);

    // Core: add a toast with { message, type, duration }
    const addToast = useCallback((message, opts = {}) => {
        const id = ++toastIdCounter;
        const type = opts.type || 'info';
        const duration = opts.duration ?? DEFAULT_DURATION;

        setToasts((prev) => [...prev, { id, message, type, duration }]);

        // Auto-dismiss after `duration` ms
        if (duration > 0) {
            timersRef.current[id] = setTimeout(() => removeToast(id), duration);
        }

        return id;
    }, [removeToast]);

    // Convenience helpers — each pre-fills the `type`
    const success = useCallback((msg, opts) => addToast(msg, { ...opts, type: 'success' }), [addToast]);
    const error = useCallback((msg, opts) => addToast(msg, { ...opts, type: 'error' }), [addToast]);
    const warning = useCallback((msg, opts) => addToast(msg, { ...opts, type: 'warning' }), [addToast]);
    const info = useCallback((msg, opts) => addToast(msg, { ...opts, type: 'info' }), [addToast]);

    // The callable object exposed via context
    const toast = useCallback((msg, opts) => addToast(msg, opts), [addToast]);
    toast.success = success;
    toast.error = error;
    toast.warning = warning;
    toast.info = info;

    return (
        <ToastContext.Provider value={toast}>
            {children}

            {/* ── Toast container — fixed bottom-right ─────────────────────── */}
            <div
                style={{
                    position: 'fixed',
                    bottom: '1.5rem',
                    right: '1.5rem',
                    zIndex: 10000,
                    display: 'flex',
                    flexDirection: 'column-reverse',
                    gap: '0.5rem',
                    pointerEvents: 'none',
                    maxHeight: '100vh',
                    overflow: 'hidden',
                }}
            >
                <AnimatePresence mode="popLayout">
                    {toasts.map((t) => {
                        const s = TOAST_STYLES[t.type] || TOAST_STYLES.info;
                        return (
                            <motion.div
                                key={t.id}
                                layout
                                initial={{ opacity: 0, x: 80, scale: 0.95 }}
                                animate={{ opacity: 1, x: 0, scale: 1 }}
                                exit={{ opacity: 0, x: 80, scale: 0.95 }}
                                transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                                style={{
                                    pointerEvents: 'auto',
                                    minWidth: 280,
                                    maxWidth: 420,
                                    background: `linear-gradient(135deg, ${s.bg}, rgba(15,23,42,0.95))`,
                                    border: `1px solid ${s.border}`,
                                    borderRadius: '0.75rem',
                                    boxShadow: `0 4px 24px ${s.glow}, 0 0 0 1px rgba(255,255,255,0.03)`,
                                    backdropFilter: 'blur(16px)',
                                    overflow: 'hidden',
                                }}
                            >
                                {/* Body */}
                                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', padding: '0.875rem 1rem' }}>
                                    {/* Icon */}
                                    <div style={{ color: s.icon, flexShrink: 0, marginTop: 2 }}>
                                        {TOAST_ICONS[t.type]}
                                    </div>

                                    {/* Message */}
                                    <span
                                        style={{
                                            flex: 1,
                                            fontSize: '0.8125rem',
                                            fontWeight: 500,
                                            color: 'rgba(255,255,255,0.9)',
                                            lineHeight: 1.5,
                                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                                        }}
                                    >
                                        {t.message}
                                    </span>

                                    {/* Dismiss */}
                                    <button
                                        onClick={() => removeToast(t.id)}
                                        style={{
                                            background: 'none',
                                            border: 'none',
                                            color: 'rgba(255,255,255,0.3)',
                                            cursor: 'pointer',
                                            padding: 2,
                                            flexShrink: 0,
                                            lineHeight: 1,
                                        }}
                                        onMouseEnter={(e) => (e.currentTarget.style.color = 'rgba(255,255,255,0.7)')}
                                        onMouseLeave={(e) => (e.currentTarget.style.color = 'rgba(255,255,255,0.3)')}
                                        aria-label="Dismiss"
                                    >
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                    </button>
                                </div>

                                {/* Progress bar (auto-dismiss countdown) */}
                                {t.duration > 0 && (
                                    <div style={{ height: 3, width: '100%', background: 'rgba(255,255,255,0.05)' }}>
                                        <motion.div
                                            initial={{ width: '100%' }}
                                            animate={{ width: '0%' }}
                                            transition={{ duration: t.duration / 1000, ease: 'linear' }}
                                            style={{
                                                height: '100%',
                                                background: s.progress,
                                                borderRadius: '0 0 0 0.75rem',
                                            }}
                                        />
                                    </div>
                                )}
                            </motion.div>
                        );
                    })}
                </AnimatePresence>
            </div>
        </ToastContext.Provider>
    );
}

export default ToastProvider;