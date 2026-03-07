import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const IndexPage = ({ onEnter }) => {
    const [typedText, setTypedText] = useState('');
    const [showButton, setShowButton] = useState(false);

    const textToType = "INITIALIZING SOVEREIGN MATRIX OS...";

    useEffect(() => {
        let i = 0;
        const typingInterval = setInterval(() => {
            if (i < textToType.length) {
                setTypedText(prev => prev + textToType.charAt(i));
                i++;
            } else {
                clearInterval(typingInterval);
                setTimeout(() => setShowButton(true), 500);
            }
        }, 50);

        return () => clearInterval(typingInterval);
    }, []);

    return (
        <div className="fixed inset-0 bg-[#050505] flex flex-col items-center justify-center z-[100] text-cyan-400 overflow-hidden">
            {/* Background Neural Grid */}
            <div className="absolute inset-0 pointer-events-none opacity-20"
                style={{
                    backgroundImage: `
            linear-gradient(rgba(6,182,212,0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(6,182,212,0.1) 1px, transparent 1px)
          `,
                    backgroundSize: '50px 50px'
                }}
            />

            <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 1.5, ease: "easeOut" }}
                className="relative z-10 flex flex-col items-center"
            >
                {/* Animated Logo */}
                <div className="relative mb-8">
                    <div className="absolute inset-0 bg-gradient-to-br from-cyan-500 to-blue-600 blur-3xl opacity-30 animate-pulse"></div>
                    <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                        className="w-32 h-32 rounded-full border border-cyan-500/30 flex items-center justify-center p-2"
                    >
                        <div className="w-full h-full rounded-full border-t-2 border-r-2 border-cyan-400 opacity-80" />
                        <motion.div
                            animate={{ rotate: -360 }}
                            transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
                            className="absolute inset-4 rounded-full border-b-2 border-l-2 border-blue-500 opacity-60"
                        />
                    </motion.div>
                    <div className="absolute inset-0 flex items-center justify-center">
                        <svg className="w-12 h-12 text-cyan-300 drop-shadow-[0_0_15px_rgba(6,182,212,0.8)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                </div>

                {/* Title */}
                <h1 className="text-5xl font-bold font-mono tracking-widest bg-gradient-to-r from-cyan-300 to-blue-500 bg-clip-text text-transparent mb-4 drop-shadow-lg">
                    NEURO-SENTRY
                </h1>

                {/* Typing Effect */}
                <div className="h-6 font-mono text-sm tracking-widest text-cyan-500/70 mb-12 flex items-center">
                    {typedText}
                    <motion.span
                        animate={{ opacity: [1, 0] }}
                        transition={{ duration: 0.8, repeat: Infinity }}
                        className="w-2 h-4 bg-cyan-400 ml-1 inline-block"
                    />
                </div>

                {/* Enter Button */}
                <AnimatePresence>
                    {showButton && (
                        <motion.button
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            whileHover={{ scale: 1.05, boxShadow: "0 0 30px rgba(6,182,212,0.4)" }}
                            whileTap={{ scale: 0.95 }}
                            onClick={onEnter}
                            className="px-10 py-4 relative group overflow-hidden rounded-lg font-mono font-bold tracking-[0.2em] text-cyan-300 border border-cyan-500/50 bg-cyan-950/30 backdrop-blur-sm transition-colors hover:bg-cyan-900/50 hover:text-white"
                        >
                            <span className="relative z-10 flex items-center gap-2">
                                ACCESS MAINFRAME
                                <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                </svg>
                            </span>
                            <div className="absolute inset-0 opacity-0 group-hover:opacity-100 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 transition-opacity" />
                        </motion.button>
                    )}
                </AnimatePresence>
            </motion.div>
        </div>
    );
};

export default IndexPage;
