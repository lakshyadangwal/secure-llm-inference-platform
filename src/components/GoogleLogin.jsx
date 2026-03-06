import { useState, useEffect } from "react";
// Google Client ID from environment variables
const CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;
export default function GoogleLogin({ onLoginSuccess, onLogout }) {
    const [user, setUser] = useState(null);
    const [sdkReady, setSdkReady] = useState(false);
    const [showDropdown, setShowDropdown] = useState(false);
    const [showModal, setShowModal] = useState(false);
    const [scanLine, setScanLine] = useState(0);
    // Restore session + load Google GSI SDK
    useEffect(() => {
        const saved = sessionStorage.getItem("ns_google_user");
        if (saved) { const u = JSON.parse(saved); setUser(u); onLoginSuccess?.(u); }
        const script = document.createElement("script");
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true; script.defer = true;
        script.onload = () => setSdkReady(true);
        document.body.appendChild(script);
        return () => document.body.removeChild(script);
    }, []);
    // Allow external components to open the login modal
    useEffect(() => {
        const handler = () => setShowModal(true);
        window.addEventListener('ns-open-login', handler);
        return () => window.removeEventListener('ns-open-login', handler);
    }, []);
    // Render the Google Sign-In button once SDK + modal are ready
    useEffect(() => {
        if (!sdkReady || user || !showModal) return;
        setTimeout(() => {
            const el = document.getElementById("ns-google-btn");
            if (!el || !window.google) return;
            window.google.accounts.id.initialize({ client_id: CLIENT_ID, callback: handleCredentialResponse });
            window.google.accounts.id.renderButton(el, { theme: "filled_black", size: "large", width: 320 });
        }, 150);
    }, [sdkReady, showModal, user]);
    // Animate scan line across modal
    useEffect(() => {
        const interval = setInterval(() => setScanLine(p => (p + 1) % 100), 30);
        return () => clearInterval(interval);
    }, []);
    function handleCredentialResponse(response) {
        const payload = JSON.parse(atob(response.credential.split(".")[1]));
        const userData = { name: payload.name, email: payload.email, picture: payload.picture };
        setUser(userData);
        sessionStorage.setItem("ns_google_user", JSON.stringify(userData));
        sessionStorage.setItem("ns_google_credential", response.credential);
        setShowModal(false);
        onLoginSuccess?.(userData);
    }
    function logout() {
        sessionStorage.removeItem("ns_google_user");
        sessionStorage.removeItem("ns_google_credential");
        setUser(null); setShowDropdown(false);
        window.google?.accounts?.id?.disableAutoSelect();
        onLogout?.();
    }
    const teal = "#00ffb4";
    return (
        <>
            <div style={{ position: "relative" }}>
                {!user ? (
                    <button onClick={() => setShowModal(true)}
                        style={{
                            display: "flex", alignItems: "center", gap: 8, padding: "7px 14px",
                            background: "transparent", border: "1px solid rgba(0,255,180,0.4)", borderRadius: 6,
                            color: teal, fontSize: 12, fontFamily: "Courier New, monospace",
                            fontWeight: 700, letterSpacing: "0.08em", cursor: "pointer", textTransform: "uppercase"
                        }}
                        onMouseEnter={e => { e.currentTarget.style.background = "rgba(0,255,180,0.08)"; e.currentTarget.style.borderColor = teal; e.currentTarget.style.boxShadow = "0 0 12px rgba(0,255,180,0.3)"; }}
                        onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.borderColor = "rgba(0,255,180,0.4)"; e.currentTarget.style.boxShadow = "none"; }}
                    >
                        <span style={{ fontSize: 14 }}>&#x2B21;</span> LOGIN
                    </button>
                ) : (
                    <button onClick={() => setShowDropdown(!showDropdown)}
                        style={{
                            display: "flex", alignItems: "center", gap: 8, padding: "5px 12px 5px 6px",
                            background: "rgba(0,255,180,0.06)", border: "1px solid rgba(0,255,180,0.5)",
                            borderRadius: 6, cursor: "pointer"
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = "rgba(0,255,180,0.12)"}
                        onMouseLeave={e => e.currentTarget.style.background = "rgba(0,255,180,0.06)"}
                    >
                        {user.picture
                            ? <img src={user.picture} alt="" style={{ width: 26, height: 26, borderRadius: "50%", border: "1px solid #00ffb4" }} />
                            : <div style={{ width: 26, height: 26, borderRadius: "50%", background: "linear-gradient(135deg,#00ffb4,#0ea5e9)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, color: "#0a0f1a" }}>{user.name.charAt(0)}</div>
                        }
                        <div>
                            <div style={{ fontSize: 11, fontFamily: "Courier New, monospace", color: teal, fontWeight: 700, lineHeight: 1.2 }}>{user.name.split(" ")[0].toUpperCase()}</div>
                            <div style={{ fontSize: 9, color: "rgba(0,255,180,0.5)" }}>AUTHORIZED</div>
                        </div>
                        <span style={{ color: "rgba(0,255,180,0.5)", fontSize: 10 }}>v</span>
                    </button>
                )}
                {showDropdown && user && (
                    <div style={{
                        position: "absolute", top: "calc(100% + 8px)", right: 0, width: 240,
                        background: "#0a0f1a", border: "1px solid rgba(0,255,180,0.3)", borderRadius: 8,
                        overflow: "hidden", boxShadow: "0 8px 32px rgba(0,0,0,0.6)", zIndex: 1000
                    }}>
                        <div style={{ padding: "14px 16px", background: "rgba(0,255,180,0.05)", borderBottom: "1px solid rgba(0,255,180,0.15)" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                {user.picture
                                    ? <img src={user.picture} alt="" style={{ width: 36, height: 36, borderRadius: "50%", border: "2px solid #00ffb4" }} />
                                    : <div style={{ width: 36, height: 36, borderRadius: "50%", background: "linear-gradient(135deg,#00ffb4,#0ea5e9)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 700, color: "#0a0f1a" }}>{user.name.charAt(0)}</div>
                                }
                                <div>
                                    <div style={{ fontSize: 13, fontWeight: 700, color: "#e2f8f0", fontFamily: "Courier New, monospace" }}>{user.name}</div>
                                    <div style={{ fontSize: 10, color: "rgba(0,255,180,0.6)" }}>{user.email}</div>
                                </div>
                            </div>
                        </div>
                        <div style={{ padding: "10px 16px", borderBottom: "1px solid rgba(255,255,255,0.05)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", fontFamily: "monospace", textTransform: "uppercase" }}>Access Level</span>
                            <span style={{ fontSize: 10, fontWeight: 700, color: teal, background: "rgba(0,255,180,0.1)", padding: "2px 8px", borderRadius: 4, fontFamily: "monospace" }}>OPERATOR</span>
                        </div>
                        <button onClick={logout}
                            style={{
                                width: "100%", padding: "11px 16px", background: "transparent", border: "none",
                                display: "flex", alignItems: "center", gap: 8, color: "rgba(255,80,80,0.8)",
                                fontSize: 12, fontFamily: "Courier New, monospace", cursor: "pointer"
                            }}
                            onMouseEnter={e => e.currentTarget.style.background = "rgba(255,80,80,0.08)"}
                            onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                        >
                            &#x23FB; TERMINATE SESSION
                        </button>
                    </div>
                )}
            </div>
            {showDropdown && <div style={{ position: "fixed", inset: 0, zIndex: 999 }} onClick={() => setShowDropdown(false)} />}

            {showModal && (
                <div style={{
                    position: "fixed", inset: 0, zIndex: 2000, background: "rgba(0,0,0,0.85)",
                    backdropFilter: "blur(6px)", display: "flex", alignItems: "center", justifyContent: "center"
                }}
                    onClick={e => { if (e.target === e.currentTarget) setShowModal(false); }}>
                    <div style={{
                        width: 400, background: "#0a0f1a", border: "1px solid rgba(0,255,180,0.3)",
                        borderRadius: 12, overflow: "hidden", boxShadow: "0 0 60px rgba(0,255,180,0.1), 0 24px 48px rgba(0,0,0,0.7)", position: "relative"
                    }}>
                        {/* scan line */}
                        <div style={{
                            position: "absolute", left: 0, right: 0, height: 2,
                            background: "linear-gradient(90deg,transparent,rgba(0,255,180,0.6),transparent)",
                            top: scanLine + "%", pointerEvents: "none", zIndex: 1
                        }} />
                        {/* Header */}
                        <div style={{ padding: "14px 20px", background: "rgba(0,255,180,0.05)", borderBottom: "1px solid rgba(0,255,180,0.15)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <div style={{ width: 8, height: 8, borderRadius: "50%", background: teal, boxShadow: "0 0 8px #00ffb4", animation: "pulse 2s infinite" }} />
                                <span style={{ fontSize: 11, fontFamily: "Courier New, monospace", color: teal, fontWeight: 700, letterSpacing: "0.1em" }}>
                                    NEURO-SENTRY // AUTH MODULE
                                </span>
                            </div>
                            <button onClick={() => setShowModal(false)} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.4)", cursor: "pointer", fontSize: 18 }}>x</button>
                        </div>
                        {/* Body */}
                        <div style={{ padding: "32px 36px 36px" }}>
                            <div style={{ textAlign: "center", marginBottom: 24 }}>
                                <div style={{
                                    display: "inline-flex", alignItems: "center", justifyContent: "center",
                                    width: 64, height: 64, borderRadius: "50%", background: "rgba(0,255,180,0.08)",
                                    border: "2px solid rgba(0,255,180,0.3)", fontSize: 28, marginBottom: 16,
                                    boxShadow: "0 0 24px rgba(0,255,180,0.15)"
                                }}>S</div>
                                <div style={{ fontSize: 20, fontWeight: 700, color: "#e2f8f0", fontFamily: "Courier New, monospace", letterSpacing: "0.05em", marginBottom: 6 }}>
                                    IDENTITY VERIFICATION
                                </div>
                                <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", lineHeight: 1.5 }}>
                                    Authenticate via Google to access<br />Neuro-Sentry command interface
                                </div>
                            </div>
                            <div style={{
                                background: "rgba(0,255,180,0.04)", border: "1px solid rgba(0,255,180,0.15)",
                                borderRadius: 8, padding: "10px 14px", marginBottom: 24, fontSize: 11,
                                fontFamily: "monospace", color: "rgba(0,255,180,0.7)", lineHeight: 1.7
                            }}>
                                <span style={{ color: teal }}>&#x25B6;</span> OAuth 2.0 secure channel active<br />
                                <span style={{ color: teal }}>&#x25B6;</span> End-to-end encryption enabled<br />
                                <span style={{ color: teal }}>&#x25B6;</span> Session token lifetime: 24h
                            </div>
                            <div id="ns-google-btn" style={{ marginBottom: 12, display: "flex", justifyContent: "center" }} />
                            <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "16px 0" }}>
                                <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
                                <span style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", fontFamily: "monospace" }}>OR</span>
                                <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
                            </div>
                            <button onClick={() => {
                                if (!window.google) return;
                                window.google.accounts.id.initialize({ client_id: CLIENT_ID, callback: handleCredentialResponse });
                                window.google.accounts.id.prompt();
                            }}
                                style={{
                                    display: "flex", alignItems: "center", justifyContent: "center", gap: 10,
                                    width: "100%", padding: 12, background: "rgba(0,255,180,0.06)",
                                    border: "1px solid rgba(0,255,180,0.35)", borderRadius: 8,
                                    fontSize: 13, fontWeight: 700, color: teal, cursor: "pointer",
                                    fontFamily: "Courier New, monospace", letterSpacing: "0.06em"
                                }}
                                onMouseEnter={e => { e.currentTarget.style.background = "rgba(0,255,180,0.12)"; e.currentTarget.style.boxShadow = "0 0 16px rgba(0,255,180,0.2)"; }}
                                onMouseLeave={e => { e.currentTarget.style.background = "rgba(0,255,180,0.06)"; e.currentTarget.style.boxShadow = "none"; }}
                            >
                                <GoogleIcon /> CONNECT WITH GOOGLE
                            </button>
                            <p style={{ fontSize: 10, color: "rgba(255,255,255,0.25)", marginTop: 20, textAlign: "center", lineHeight: 1.6, fontFamily: "monospace" }}>
                                AUTHENTICATION REQUIRED FOR FULL SYSTEM ACCESS<br />
                                SESSION DATA IS ENCRYPTED AND NOT SHARED
                            </p>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}