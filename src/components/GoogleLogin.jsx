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
}