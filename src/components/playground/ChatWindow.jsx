import React, { useState, useRef, useEffect } from 'react';
import MessageBubble from './MessageBubble';
import { Send, Shield, ShieldAlert, Loader2 } from 'lucide-react';

const ChatWindow = ({ model, temperature, systemPrompt, securityEnabled }) => {
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const messagesEndRef = useRef(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const handleSend = async () => {
        if (!input.trim()) return;

        const userMessage = { role: 'user', content: input };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        // Prepare API payload
        const payload = {
            messages: [
                { role: 'system', content: systemPrompt },
                ...messages.map(m => ({ role: m.role, content: m.content })),
                userMessage
            ],
            model: model,
            temperature: temperature,
            security_enabled: securityEnabled
        };

        try {
            const response = await fetch('http://localhost:8000/api/playground/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    // 'Authorization': `Bearer ${localStorage.getItem('token')}` // If needed
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            setMessages(prev => [...prev, {
                role: 'assistant',
                content: data.response,
                meta: {
                    latency: data.latency_ms,
                    breach: data.breach_detected,
                    threatType: data.threat_type,
                    blockedBy: data.blocked_by
                }
            }]);
        } catch (error) {
            console.error("Chat error:", error);
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: "Error communicating with the server.",
                meta: { error: true }
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="flex flex-col h-full bg-gray-900 overflow-hidden">
            {/* Header */}
            <div className="p-4 bg-gray-800 border-b border-gray-700 flex justify-between items-center z-10">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    {securityEnabled ? <Shield className="text-green-400 w-5 h-5" /> : <ShieldAlert className="text-red-500 w-5 h-5" />}
                    Inference Stream
                </h3>
                <div className="text-xs text-gray-400">
                    Using {model} • Temp: {temperature}
                </div>
            </div>

            {/* Message Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {messages.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full text-gray-500">
                        <p>Send a message to begin testing the LLM with security policies.</p>
                    </div>
                ) : null}

                {messages.map((msg, idx) => (
                    <MessageBubble key={idx} message={msg} />
                ))}

                {isLoading && (
                    <div className="flex bg-gray-800 self-start p-3 rounded-xl border border-gray-700 w-fit">
                        <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="p-4 bg-gray-800 border-t border-gray-700">
                <div className="flex items-center bg-gray-900 border border-gray-700 rounded-lg overflow-hidden focus-within:border-cyan-500 transition-colors">
                    <input
                        type="text"
                        className="flex-1 bg-transparent text-white px-4 py-3 outline-none"
                        placeholder="Type a message or prompt injection to test..."
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                        disabled={isLoading}
                    />
                    <button
                        onClick={handleSend}
                        disabled={isLoading}
                        className="px-4 py-3 bg-cyan-600 hover:bg-cyan-500 transition-colors text-white font-semibold flex items-center justify-center disabled:opacity-50"
                    >
                        <Send className="w-5 h-5" />
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ChatWindow;
