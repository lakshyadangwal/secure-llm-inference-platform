import React from 'react';
import { Shield, ShieldAlert, Cpu, User } from 'lucide-react';

const MessageBubble = ({ message }) => {
    const isUser = message.role === 'user';
    const isSystem = message.role === 'system';

    const meta = message.meta || {};

    return (
        <div className={`flex w-full ${isUser ? 'justify-end' : 'justify-start'} mb-4`}>
            <div className={`
        flex gap-3 max-w-[80%] 
        ${isUser ? 'flex-row-reverse' : 'flex-row'}
      `}>
                {/* Avatar */}
                <div className={`
          flex items-center justify-center h-10 w-10 rounded-full shrink-0
          ${isUser ? 'bg-cyan-600' : isSystem ? 'bg-gray-700 text-yellow-400' : meta.breach ? 'bg-red-900/50 border border-red-500 text-red-400' : 'bg-green-900/50 border border-green-500 text-green-400'}
        `}>
                    {isUser ? <User className="w-6 h-6 text-white" /> : isSystem ? <Shield className="w-5 h-5" /> : meta.breach ? <ShieldAlert className="w-5 h-5" /> : <Cpu className="w-5 h-5" />}
                </div>

                {/* Bubble Content */}
                <div className={`
          flex flex-col gap-1 
          ${isUser ? 'items-end' : 'items-start'}
        `}>
                    <div className="flex items-center gap-2 px-1 text-xs text-gray-400">
                        <span className="font-semibold uppercase">{message.role}</span>
                        {meta.latency && <span>• {meta.latency.toFixed(0)} ms</span>}
                    </div>

                    <div className={`
            px-5 py-3 rounded-2xl text-sm leading-relaxed whitespace-pre-wrap
            ${isUser ? 'bg-cyan-600 text-white rounded-tr-none' :
                            isSystem ? 'bg-gray-800 border border-gray-700 text-gray-300 rounded-tl-none' :
                                meta.breach ? 'bg-red-900/30 border border-red-500/50 text-red-200 rounded-tl-none relative shadow-[0_0_15px_rgba(239,68,68,0.2)]' :
                                    'bg-gray-800 border border-green-500/30 text-gray-200 rounded-tl-none'}
          `}>
                        {message.content}
                    </div>

                    {/* Meta Tags for Assistant Responses */}
                    {!isUser && !isSystem && (
                        <div className="flex gap-2 mt-1 px-1">
                            {meta.breach ? (
                                <>
                                    <span className="text-xs bg-red-900/50 text-red-400 border border-red-800 px-2 py-0.5 rounded-md">
                                        Blocked by {meta.blockedBy || 'Security'}
                                    </span>
                                    <span className="text-xs bg-red-900/30 text-red-300 border border-red-800 px-2 py-0.5 rounded-md">
                                        Threat: {meta.threatType}
                                    </span>
                                </>
                            ) : (
                                <span className="text-xs bg-green-900/30 text-green-400 border border-green-800 px-2 py-0.5 rounded-md">
                                    Safe Content
                                </span>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default MessageBubble;
