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
        </>
    );
}