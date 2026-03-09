/**
 * Advanced Network Security Utilities
 * Provides comprehensive network-level security analysis, request validation,
 * rate limiting, IP reputation, and threat detection utilities.
 *
 * @module networkSecurity
 * @version 2.0.0
 */

// ============================================================================
// IP Address Utilities
// ============================================================================

/**
 * Determines if an IP address is in a private/reserved range.
 * @param {string} ip - The IP address to check
 * @returns {boolean} True if the IP is private
 */
export function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    return false;
}

/**
 * Validates an IPv4 address format.
 * @param {string} ip - The IP address to validate
 * @returns {boolean} True if valid IPv4
 */
export function isValidIPv4(ip) {
    const pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(pattern);
    if (!match) return false;
    return match.slice(1).every(octet => {
        const num = parseInt(octet, 10);
        return num >= 0 && num <= 255 && octet === num.toString();
    });
}

/**
 * Validates an IPv6 address format.
 * @param {string} ip - The IP address to validate
 * @returns {boolean} True if valid IPv6
 */
export function isValidIPv6(ip) {
    const pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?$/;
    return pattern.test(ip);
}

/**
 * Checks if an IP is within a CIDR range.
 * @param {string} ip - The IP address to check
 * @param {string} cidr - The CIDR range (e.g., "192.168.1.0/24")
 * @returns {boolean} True if the IP is within the range
 */
export function isIPInCIDR(ip, cidr) {
    const [rangeIP, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);
    const ipNum = ipToNumber(ip);
    const rangeNum = ipToNumber(rangeIP);
    return (ipNum & mask) === (rangeNum & mask);
}

/**
 * Converts an IPv4 address to a 32-bit number.
 * @param {string} ip - The IP address
 * @returns {number} The numeric representation
 */
export function ipToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
}

/**
 * Converts a 32-bit number back to an IPv4 address.
 * @param {number} num - The numeric IP
 * @returns {string} The IP address string
 */
export function numberToIP(num) {
    return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
}

/**
 * Calculates the broadcast address for a CIDR range.
 * @param {string} cidr - The CIDR range
 * @returns {string} The broadcast address
 */
export function getCIDRBroadcast(cidr) {
    const [ip, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1) >>> 0;
    const network = ipToNumber(ip) & mask;
    const broadcast = network | (~mask >>> 0);
    return numberToIP(broadcast);
}

/**
 * Gets the network address for a CIDR range.
 * @param {string} cidr - The CIDR range
 * @returns {string} The network address
 */
export function getCIDRNetwork(cidr) {
    const [ip, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1) >>> 0;
    return numberToIP(ipToNumber(ip) & mask);
}

/**
 * Counts the number of usable hosts in a CIDR range.
 * @param {string} cidr - The CIDR range
 * @returns {number} Number of usable host addresses
 */
export function getCIDRHostCount(cidr) {
    const bits = parseInt(cidr.split('/')[1]);
    if (bits >= 31) return bits === 31 ? 2 : 1;
    return Math.pow(2, 32 - bits) - 2;
}

// ============================================================================
// Request Fingerprinting
// ============================================================================

/**
 * Generates a browser fingerprint based on available attributes.
 * @returns {Object} The fingerprint data
 */
export function generateBrowserFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Neuro-Sentry FP', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Neuro-Sentry FP', 4, 17);
    const canvasHash = canvas.toDataURL();

    const screenData = {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio || 1,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
    };

    const navigatorData = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages ? [...navigator.languages] : [],
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        maxTouchPoints: navigator.maxTouchPoints || 0,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,
        online: navigator.onLine,
    };

    const timezoneData = {
        offset: new Date().getTimezoneOffset(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    };

    const plugins = [];
    if (navigator.plugins) {
        for (let i = 0; i < Math.min(navigator.plugins.length, 20); i++) {
            plugins.push({
                name: navigator.plugins[i].name,
                filename: navigator.plugins[i].filename,
            });
        }
    }

    const webglData = getWebGLFingerprint();

    return {
        canvas: canvasHash.substring(0, 100),
        screen: screenData,
        navigator: navigatorData,
        timezone: timezoneData,
        plugins,
        webgl: webglData,
        timestamp: Date.now(),
    };
}

/**
 * Extracts WebGL renderer information for fingerprinting.
 * @returns {Object} WebGL fingerprint data
 */
function getWebGLFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return { supported: false };

        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        return {
            supported: true,
            vendor: gl.getParameter(gl.VENDOR),
            renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
            vendorUnmasked: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
            maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
            maxCombinedTextureImageUnits: gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS),
            extensions: gl.getSupportedExtensions() || [],
        };
    } catch (e) {
        return { supported: false, error: e.message };
    }
}

// ============================================================================
// Rate Limiting (Client-Side)
// ============================================================================

/**
 * Token bucket rate limiter implementation.
 */
export class TokenBucketRateLimiter {
    constructor(maxTokens, refillRate, refillIntervalMs = 1000) {
        this.maxTokens = maxTokens;
        this.tokens = maxTokens;
        this.refillRate = refillRate;
        this.refillIntervalMs = refillIntervalMs;
        this.lastRefill = Date.now();
        this.requestLog = [];
        this.blockedCount = 0;
        this.totalRequests = 0;
    }

    refill() {
        const now = Date.now();
        const elapsed = now - this.lastRefill;
        const tokensToAdd = Math.floor(elapsed / this.refillIntervalMs) * this.refillRate;
        if (tokensToAdd > 0) {
            this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
            this.lastRefill = now;
        }
    }

    tryConsume(tokens = 1) {
        this.totalRequests++;
        this.refill();
        if (this.tokens >= tokens) {
            this.tokens -= tokens;
            this.requestLog.push({ timestamp: Date.now(), allowed: true, tokens });
            return true;
        }
        this.blockedCount++;
        this.requestLog.push({ timestamp: Date.now(), allowed: false, tokens });
        return false;
    }

    getWaitTime(tokens = 1) {
        this.refill();
        if (this.tokens >= tokens) return 0;
        const deficit = tokens - this.tokens;
        return Math.ceil(deficit / this.refillRate) * this.refillIntervalMs;
    }

    getStats() {
        const now = Date.now();
        const recentWindow = 60000;
        const recentRequests = this.requestLog.filter(r => now - r.timestamp < recentWindow);
        return {
            currentTokens: this.tokens,
            maxTokens: this.maxTokens,
            totalRequests: this.totalRequests,
            blockedRequests: this.blockedCount,
            blockRate: this.totalRequests > 0 ? (this.blockedCount / this.totalRequests * 100).toFixed(2) + '%' : '0%',
            recentRequestCount: recentRequests.length,
            recentBlockedCount: recentRequests.filter(r => !r.allowed).length,
        };
    }

    reset() {
        this.tokens = this.maxTokens;
        this.lastRefill = Date.now();
        this.requestLog = [];
        this.blockedCount = 0;
        this.totalRequests = 0;
    }
}

/**
 * Sliding window rate limiter implementation.
 */
export class SlidingWindowRateLimiter {
    constructor(windowMs, maxRequests) {
        this.windowMs = windowMs;
        this.maxRequests = maxRequests;
        this.windows = new Map();
    }

    _getKey(identifier) {
        return identifier || 'default';
    }

    _cleanWindow(key) {
        const now = Date.now();
        const cutoff = now - this.windowMs;
        const window = this.windows.get(key) || [];
        const cleaned = window.filter(ts => ts > cutoff);
        this.windows.set(key, cleaned);
        return cleaned;
    }

    tryConsume(identifier = null) {
        const key = this._getKey(identifier);
        const window = this._cleanWindow(key);
        if (window.length >= this.maxRequests) {
            return { allowed: false, remaining: 0, resetMs: window[0] + this.windowMs - Date.now() };
        }
        window.push(Date.now());
        this.windows.set(key, window);
        return { allowed: true, remaining: this.maxRequests - window.length, resetMs: this.windowMs };
    }

    getRemaining(identifier = null) {
        const key = this._getKey(identifier);
        const window = this._cleanWindow(key);
        return Math.max(0, this.maxRequests - window.length);
    }

    reset(identifier = null) {
        if (identifier) {
            this.windows.delete(this._getKey(identifier));
        } else {
            this.windows.clear();
        }
    }
}

/**
 * Leaky bucket rate limiter implementation.
 */
export class LeakyBucketRateLimiter {
    constructor(capacity, leakRate) {
        this.capacity = capacity;
        this.leakRate = leakRate;
        this.water = 0;
        this.lastLeak = Date.now();
        this.overflowCount = 0;
    }

    _leak() {
        const now = Date.now();
        const elapsed = (now - this.lastLeak) / 1000;
        const leaked = elapsed * this.leakRate;
        this.water = Math.max(0, this.water - leaked);
        this.lastLeak = now;
    }

    tryAdd(amount = 1) {
        this._leak();
        if (this.water + amount > this.capacity) {
            this.overflowCount++;
            return false;
        }
        this.water += amount;
        return true;
    }

    getCurrentLevel() {
        this._leak();
        return { level: this.water, capacity: this.capacity, percentage: (this.water / this.capacity * 100).toFixed(1) + '%' };
    }
}

// ============================================================================
// Request Validation & Sanitization
// ============================================================================

/**
 * Validates and sanitizes HTTP headers for potential injection attacks.
 * @param {Object} headers - The headers to validate
 * @returns {Object} Validation result
 */
export function validateHeaders(headers) {
    const issues = [];
    const dangerousPatterns = [
        /[\r\n]/,
        /<script/i,
        /javascript:/i,
        /data:text\/html/i,
        /vbscript:/i,
    ];

    const sensitiveHeaders = [
        'authorization', 'cookie', 'set-cookie', 'x-forwarded-for',
        'x-real-ip', 'proxy-authorization', 'www-authenticate',
    ];

    for (const [key, value] of Object.entries(headers)) {
        const valueStr = String(value);
        for (const pattern of dangerousPatterns) {
            if (pattern.test(key) || pattern.test(valueStr)) {
                issues.push({ header: key, issue: 'dangerous_pattern', pattern: pattern.toString() });
            }
        }
        if (valueStr.length > 8192) {
            issues.push({ header: key, issue: 'excessive_length', length: valueStr.length });
        }
        if (sensitiveHeaders.includes(key.toLowerCase())) {
            issues.push({ header: key, issue: 'sensitive_header', severity: 'info' });
        }
    }

    return { valid: issues.filter(i => i.severity !== 'info').length === 0, issues, checkedAt: Date.now() };
}

/**
 * Validates URL for potential SSRF attacks.
 * @param {string} url - The URL to validate
 * @param {Object} options - Validation options
 * @returns {Object} Validation result
 */
export function validateURLSecurity(url, options = {}) {
    const {
        allowPrivateIPs = false,
        allowedProtocols = ['https:', 'http:'],
        blockedPorts = [22, 23, 25, 3389, 5900],
        maxRedirects = 5,
    } = options;

    const issues = [];

    try {
        const parsed = new URL(url);
        if (!allowedProtocols.includes(parsed.protocol)) {
            issues.push({ issue: 'disallowed_protocol', protocol: parsed.protocol });
        }
        if (parsed.port && blockedPorts.includes(parseInt(parsed.port))) {
            issues.push({ issue: 'blocked_port', port: parsed.port });
        }
        if (parsed.username || parsed.password) {
            issues.push({ issue: 'embedded_credentials' });
        }
        if (!allowPrivateIPs && parsed.hostname) {
            const hostname = parsed.hostname;
            if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname.startsWith('127.') ||
                hostname === '::1' || hostname === '[::1]' || hostname.endsWith('.local') ||
                hostname.endsWith('.internal')) {
                issues.push({ issue: 'private_address', hostname });
            }
            if (isValidIPv4(hostname) && isPrivateIP(hostname)) {
                issues.push({ issue: 'private_ip', ip: hostname });
            }
        }
        if (parsed.href.includes('..') || parsed.href.includes('%2e%2e') || parsed.href.includes('%252e')) {
            issues.push({ issue: 'path_traversal_attempt' });
        }
        if (parsed.hash && parsed.hash.length > 256) {
            issues.push({ issue: 'excessive_fragment_length' });
        }
    } catch (e) {
        issues.push({ issue: 'invalid_url', error: e.message });
    }

    return {
        valid: issues.length === 0,
        issues,
        maxRedirects,
        checkedAt: Date.now(),
    };
}

/**
 * Sanitizes user input to prevent XSS attacks.
 * @param {string} input - The input to sanitize
 * @returns {string} The sanitized input
 */
export function sanitizeInput(input) {
    if (typeof input !== 'string') return String(input);
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        .replace(/\\/g, '&#x5C;')
        .replace(/`/g, '&#96;');
}

/**
 * Deep sanitizes an object recursively.
 * @param {*} obj - The object to sanitize
 * @param {number} depth - Maximum recursion depth
 * @returns {*} The sanitized object
 */
export function deepSanitize(obj, depth = 10) {
    if (depth <= 0) return '[MAX_DEPTH]';
    if (typeof obj === 'string') return sanitizeInput(obj);
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(item => deepSanitize(item, depth - 1));
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        sanitized[sanitizeInput(key)] = deepSanitize(value, depth - 1);
    }
    return sanitized;
}

// ============================================================================
// Content Security Policy Builder
// ============================================================================

/**
 * Builder class for constructing Content Security Policy headers.
 */
export class CSPBuilder {
    constructor() {
        this.directives = {};
        this.reportUri = null;
        this.reportTo = null;
    }

    addDirective(name, ...values) {
        if (!this.directives[name]) this.directives[name] = [];
        this.directives[name].push(...values);
        return this;
    }

    defaultSrc(...sources) { return this.addDirective('default-src', ...sources); }
    scriptSrc(...sources) { return this.addDirective('script-src', ...sources); }
    styleSrc(...sources) { return this.addDirective('style-src', ...sources); }
    imgSrc(...sources) { return this.addDirective('img-src', ...sources); }
    connectSrc(...sources) { return this.addDirective('connect-src', ...sources); }
    fontSrc(...sources) { return this.addDirective('font-src', ...sources); }
    objectSrc(...sources) { return this.addDirective('object-src', ...sources); }
    mediaSrc(...sources) { return this.addDirective('media-src', ...sources); }
    frameSrc(...sources) { return this.addDirective('frame-src', ...sources); }
    childSrc(...sources) { return this.addDirective('child-src', ...sources); }
    workerSrc(...sources) { return this.addDirective('worker-src', ...sources); }
    formAction(...sources) { return this.addDirective('form-action', ...sources); }
    frameAncestors(...sources) { return this.addDirective('frame-ancestors', ...sources); }
    baseUri(...sources) { return this.addDirective('base-uri', ...sources); }
    manifestSrc(...sources) { return this.addDirective('manifest-src', ...sources); }

    upgradeInsecureRequests() {
        this.directives['upgrade-insecure-requests'] = [];
        return this;
    }

    blockAllMixedContent() {
        this.directives['block-all-mixed-content'] = [];
        return this;
    }

    setReportUri(uri) {
        this.reportUri = uri;
        return this;
    }

    setReportTo(groupName) {
        this.reportTo = groupName;
        return this;
    }

    build() {
        const parts = [];
        for (const [directive, values] of Object.entries(this.directives)) {
            if (values.length === 0) {
                parts.push(directive);
            } else {
                parts.push(`${directive} ${values.join(' ')}`);
            }
        }
        if (this.reportUri) parts.push(`report-uri ${this.reportUri}`);
        if (this.reportTo) parts.push(`report-to ${this.reportTo}`);
        return parts.join('; ');
    }

    static strict() {
        return new CSPBuilder()
            .defaultSrc("'none'")
            .scriptSrc("'self'")
            .styleSrc("'self'", "'unsafe-inline'")
            .imgSrc("'self'", 'data:')
            .connectSrc("'self'")
            .fontSrc("'self'")
            .objectSrc("'none'")
            .frameAncestors("'none'")
            .baseUri("'self'")
            .formAction("'self'")
            .upgradeInsecureRequests();
    }

    static permissive() {
        return new CSPBuilder()
            .defaultSrc("'self'")
            .scriptSrc("'self'", "'unsafe-inline'", "'unsafe-eval'")
            .styleSrc("'self'", "'unsafe-inline'")
            .imgSrc('*', 'data:', 'blob:')
            .connectSrc('*')
            .fontSrc('*')
            .frameSrc('*');
    }
}

// ============================================================================
// Security Headers Analyzer
// ============================================================================

/**
 * Analyzes HTTP response headers for security best practices.
 * @param {Object} headers - The response headers
 * @returns {Object} Analysis results with scores and recommendations
 */
export function analyzeSecurityHeaders(headers) {
    const results = { score: 0, maxScore: 0, findings: [], grade: 'F' };
    const checks = [
        { header: 'Content-Security-Policy', weight: 3, required: true },
        { header: 'Strict-Transport-Security', weight: 3, required: true, minMaxAge: 31536000 },
        { header: 'X-Content-Type-Options', weight: 2, required: true, expectedValue: 'nosniff' },
        { header: 'X-Frame-Options', weight: 2, required: true },
        { header: 'X-XSS-Protection', weight: 1, required: false },
        { header: 'Referrer-Policy', weight: 2, required: true },
        { header: 'Permissions-Policy', weight: 2, required: false },
        { header: 'Cross-Origin-Opener-Policy', weight: 1, required: false },
        { header: 'Cross-Origin-Resource-Policy', weight: 1, required: false },
        { header: 'Cross-Origin-Embedder-Policy', weight: 1, required: false },
    ];

    for (const check of checks) {
        results.maxScore += check.weight;
        const headerKey = Object.keys(headers).find(h => h.toLowerCase() === check.header.toLowerCase());
        const value = headerKey ? headers[headerKey] : null;

        if (!value) {
            results.findings.push({
                header: check.header,
                status: 'missing',
                severity: check.required ? 'high' : 'medium',
                recommendation: `Add ${check.header} header`,
            });
        } else {
            let valid = true;
            if (check.expectedValue && value.toLowerCase() !== check.expectedValue.toLowerCase()) {
                valid = false;
                results.findings.push({
                    header: check.header,
                    status: 'incorrect',
                    value,
                    expected: check.expectedValue,
                    severity: 'medium',
                });
            }
            if (check.minMaxAge) {
                const maxAgeMatch = value.match(/max-age=(\d+)/);
                if (!maxAgeMatch || parseInt(maxAgeMatch[1]) < check.minMaxAge) {
                    valid = false;
                    results.findings.push({
                        header: check.header,
                        status: 'weak',
                        value,
                        recommendation: `Set max-age to at least ${check.minMaxAge}`,
                        severity: 'medium',
                    });
                }
            }
            if (valid) results.score += check.weight;
        }
    }

    const dangerousHeaders = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version'];
    for (const dh of dangerousHeaders) {
        const found = Object.keys(headers).find(h => h.toLowerCase() === dh.toLowerCase());
        if (found) {
            results.findings.push({
                header: found,
                status: 'information_disclosure',
                value: headers[found],
                severity: 'low',
                recommendation: `Remove ${found} header to prevent information disclosure`,
            });
        }
    }

    const pct = results.maxScore > 0 ? (results.score / results.maxScore) * 100 : 0;
    if (pct >= 90) results.grade = 'A';
    else if (pct >= 80) results.grade = 'B';
    else if (pct >= 65) results.grade = 'C';
    else if (pct >= 50) results.grade = 'D';
    else results.grade = 'F';

    results.percentage = pct.toFixed(1) + '%';
    results.analyzedAt = Date.now();
    return results;
}

// ============================================================================
// TLS/SSL Utilities
// ============================================================================

/**
 * Parses TLS certificate information from a connection.
 * @param {Object} certInfo - Certificate metadata
 * @returns {Object} Parsed certificate details
 */
export function parseCertificateInfo(certInfo) {
    const now = new Date();
    const validFrom = new Date(certInfo.validFrom || certInfo.valid_from);
    const validTo = new Date(certInfo.validTo || certInfo.valid_to);
    const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

    return {
        subject: certInfo.subject || {},
        issuer: certInfo.issuer || {},
        serialNumber: certInfo.serialNumber || certInfo.serial_number || 'unknown',
        validFrom: validFrom.toISOString(),
        validTo: validTo.toISOString(),
        daysUntilExpiry,
        isExpired: now > validTo,
        isNotYetValid: now < validFrom,
        isExpiringSoon: daysUntilExpiry <= 30 && daysUntilExpiry > 0,
        keySize: certInfo.bits || certInfo.keySize || 0,
        signatureAlgorithm: certInfo.sigalg || certInfo.signatureAlgorithm || 'unknown',
        fingerprint: certInfo.fingerprint || certInfo.fingerprint256 || 'unknown',
        subjectAltNames: certInfo.subjectaltname ? certInfo.subjectaltname.split(', ') : [],
        isWildcard: (certInfo.subject?.CN || '').startsWith('*.'),
        isSelfSigned: JSON.stringify(certInfo.subject) === JSON.stringify(certInfo.issuer),
        warnings: [],
    };
}

/**
 * Evaluates TLS configuration security.
 * @param {Object} tlsConfig - TLS configuration details
 * @returns {Object} Security evaluation
 */
export function evaluateTLSSecurity(tlsConfig) {
    const issues = [];
    const weakProtocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];
    const weakCiphers = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon',
        'RC2', 'IDEA', 'SEED', 'CAMELLIA',
    ];

    if (tlsConfig.protocol && weakProtocols.includes(tlsConfig.protocol)) {
        issues.push({ issue: 'weak_protocol', protocol: tlsConfig.protocol, severity: 'critical' });
    }

    if (tlsConfig.cipher) {
        for (const weak of weakCiphers) {
            if (tlsConfig.cipher.toUpperCase().includes(weak)) {
                issues.push({ issue: 'weak_cipher', cipher: tlsConfig.cipher, weakComponent: weak, severity: 'high' });
                break;
            }
        }
    }

    if (tlsConfig.keySize && tlsConfig.keySize < 2048) {
        issues.push({ issue: 'small_key_size', keySize: tlsConfig.keySize, severity: 'high' });
    }

    const secureProtocols = ['TLSv1.2', 'TLSv1.3'];
    const hasSecureProtocol = tlsConfig.protocol && secureProtocols.includes(tlsConfig.protocol);
    const hasPFS = tlsConfig.cipher && (tlsConfig.cipher.includes('ECDHE') || tlsConfig.cipher.includes('DHE'));

    let grade = 'A';
    if (issues.some(i => i.severity === 'critical')) grade = 'F';
    else if (issues.some(i => i.severity === 'high')) grade = 'D';
    else if (!hasSecureProtocol) grade = 'C';
    else if (!hasPFS) grade = 'B';

    return {
        grade,
        issues,
        hasSecureProtocol,
        hasPerfectForwardSecrecy: hasPFS,
        protocol: tlsConfig.protocol,
        cipher: tlsConfig.cipher,
        evaluatedAt: Date.now(),
    };
}

// ============================================================================
// Network Anomaly Detection
// ============================================================================

/**
 * Detects anomalies in network request patterns.
 */
export class NetworkAnomalyDetector {
    constructor(options = {}) {
        this.windowSize = options.windowSize || 60000;
        this.maxRequestsPerWindow = options.maxRequestsPerWindow || 100;
        this.burstThreshold = options.burstThreshold || 10;
        this.burstWindowMs = options.burstWindowMs || 1000;
        this.suspiciousUserAgents = options.suspiciousUserAgents || [
            'curl', 'wget', 'python-requests', 'scrapy', 'bot', 'crawler', 'spider',
            'httpclient', 'java/', 'php/', 'go-http-client',
        ];
        this.requestHistory = [];
        this.alerts = [];
    }

    recordRequest(metadata) {
        const entry = {
            timestamp: Date.now(),
            url: metadata.url || '',
            method: metadata.method || 'GET',
            userAgent: metadata.userAgent || '',
            ip: metadata.ip || '',
            statusCode: metadata.statusCode || 0,
            responseTime: metadata.responseTime || 0,
            size: metadata.size || 0,
        };
        this.requestHistory.push(entry);
        this._cleanup();
        this._analyze(entry);
        return entry;
    }

    _cleanup() {
        const cutoff = Date.now() - this.windowSize * 2;
        this.requestHistory = this.requestHistory.filter(r => r.timestamp > cutoff);
    }

    _analyze(entry) {
        this._checkRateAnomaly(entry);
        this._checkBurstAnomaly(entry);
        this._checkUserAgentAnomaly(entry);
        this._checkPathAnomaly(entry);
        this._checkResponseTimeAnomaly(entry);
        this._checkStatusCodeAnomaly(entry);
    }

    _checkRateAnomaly(entry) {
        const windowRequests = this.requestHistory.filter(
            r => entry.timestamp - r.timestamp < this.windowSize
        );
        if (windowRequests.length > this.maxRequestsPerWindow) {
            this._addAlert('rate_anomaly', 'high', {
                requestCount: windowRequests.length,
                threshold: this.maxRequestsPerWindow,
                windowMs: this.windowSize,
            });
        }
    }

    _checkBurstAnomaly(entry) {
        const burstRequests = this.requestHistory.filter(
            r => entry.timestamp - r.timestamp < this.burstWindowMs
        );
        if (burstRequests.length > this.burstThreshold) {
            this._addAlert('burst_anomaly', 'medium', {
                burstCount: burstRequests.length,
                threshold: this.burstThreshold,
                windowMs: this.burstWindowMs,
            });
        }
    }

    _checkUserAgentAnomaly(entry) {
        if (!entry.userAgent) {
            this._addAlert('missing_user_agent', 'low', { url: entry.url });
            return;
        }
        const ua = entry.userAgent.toLowerCase();
        for (const suspicious of this.suspiciousUserAgents) {
            if (ua.includes(suspicious.toLowerCase())) {
                this._addAlert('suspicious_user_agent', 'medium', { userAgent: entry.userAgent, matchedPattern: suspicious });
                break;
            }
        }
    }

    _checkPathAnomaly(entry) {
        const suspiciousPatterns = [
            /\.\.\//,
            /\/etc\/(passwd|shadow|hosts)/,
            /\/proc\//,
            /\.(env|git|svn|htaccess|htpasswd)/,
            /admin|phpmyadmin|wp-admin|wp-login/i,
            /\.(asp|aspx|jsp|cgi|pl)$/i,
            /union\s+select/i,
            /script>/i,
            /%00/,
            /%0[aAdD]/,
        ];
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(entry.url)) {
                this._addAlert('suspicious_path', 'high', { url: entry.url, pattern: pattern.toString() });
                break;
            }
        }
    }

    _checkResponseTimeAnomaly(entry) {
        if (entry.responseTime <= 0) return;
        const recentTimes = this.requestHistory
            .filter(r => r.responseTime > 0)
            .map(r => r.responseTime);
        if (recentTimes.length < 5) return;
        const avg = recentTimes.reduce((s, t) => s + t, 0) / recentTimes.length;
        const stdDev = Math.sqrt(recentTimes.reduce((s, t) => s + Math.pow(t - avg, 2), 0) / recentTimes.length);
        if (entry.responseTime > avg + 3 * stdDev) {
            this._addAlert('response_time_anomaly', 'low', {
                responseTime: entry.responseTime,
                average: Math.round(avg),
                stdDev: Math.round(stdDev),
            });
        }
    }

    _checkStatusCodeAnomaly(entry) {
        if (entry.statusCode >= 500) {
            this._addAlert('server_error', 'high', { statusCode: entry.statusCode, url: entry.url });
        } else if (entry.statusCode === 403 || entry.statusCode === 401) {
            const recentAuthFailures = this.requestHistory.filter(
                r => (r.statusCode === 401 || r.statusCode === 403) && entry.timestamp - r.timestamp < 60000
            );
            if (recentAuthFailures.length > 5) {
                this._addAlert('brute_force_attempt', 'critical', { failureCount: recentAuthFailures.length });
            }
        }
    }

    _addAlert(type, severity, details) {
        this.alerts.push({ type, severity, details, timestamp: Date.now() });
        if (this.alerts.length > 1000) this.alerts = this.alerts.slice(-500);
    }

    getAlerts(since = 0) {
        return this.alerts.filter(a => a.timestamp > since);
    }

    getStats() {
        const now = Date.now();
        return {
            totalRequests: this.requestHistory.length,
            recentAlerts: this.alerts.filter(a => now - a.timestamp < 300000).length,
            alertsByType: this.alerts.reduce((acc, a) => { acc[a.type] = (acc[a.type] || 0) + 1; return acc; }, {}),
            alertsBySeverity: this.alerts.reduce((acc, a) => { acc[a.severity] = (acc[a.severity] || 0) + 1; return acc; }, {}),
        };
    }

    reset() {
        this.requestHistory = [];
        this.alerts = [];
    }
}

// ============================================================================
// CORS Configuration Helper
// ============================================================================

/**
 * CORS configuration builder and validator.
 */
export class CORSConfigBuilder {
    constructor() {
        this.config = {
            allowedOrigins: [],
            allowedMethods: ['GET', 'POST'],
            allowedHeaders: ['Content-Type'],
            exposedHeaders: [],
            maxAge: 86400,
            credentials: false,
        };
    }

    allowOrigin(origin) { this.config.allowedOrigins.push(origin); return this; }
    allowOrigins(origins) { this.config.allowedOrigins.push(...origins); return this; }
    allowMethod(method) { this.config.allowedMethods.push(method.toUpperCase()); return this; }
    allowMethods(methods) { this.config.allowedMethods.push(...methods.map(m => m.toUpperCase())); return this; }
    allowHeader(header) { this.config.allowedHeaders.push(header); return this; }
    allowHeaders(headers) { this.config.allowedHeaders.push(...headers); return this; }
    exposeHeader(header) { this.config.exposedHeaders.push(header); return this; }
    setMaxAge(seconds) { this.config.maxAge = seconds; return this; }
    withCredentials() { this.config.credentials = true; return this; }

    validate() {
        const issues = [];
        if (this.config.allowedOrigins.includes('*') && this.config.credentials) {
            issues.push('Cannot use wildcard origin with credentials');
        }
        if (this.config.allowedMethods.includes('*')) {
            issues.push('Wildcard methods are not recommended');
        }
        if (this.config.maxAge > 86400) {
            issues.push('Max age exceeds recommended 24 hours');
        }
        return { valid: issues.length === 0, issues };
    }

    build() {
        const validation = this.validate();
        if (!validation.valid) {
            console.warn('CORS configuration issues:', validation.issues);
        }
        return {
            ...this.config,
            allowedOrigins: [...new Set(this.config.allowedOrigins)],
            allowedMethods: [...new Set(this.config.allowedMethods)],
            allowedHeaders: [...new Set(this.config.allowedHeaders)],
            exposedHeaders: [...new Set(this.config.exposedHeaders)],
        };
    }
}

// ============================================================================
// Exports
// ============================================================================

export default {
    isPrivateIP, isValidIPv4, isValidIPv6, isIPInCIDR, ipToNumber, numberToIP,
    getCIDRBroadcast, getCIDRNetwork, getCIDRHostCount,
    generateBrowserFingerprint,
    TokenBucketRateLimiter, SlidingWindowRateLimiter, LeakyBucketRateLimiter,
    validateHeaders, validateURLSecurity, sanitizeInput, deepSanitize,
    CSPBuilder, analyzeSecurityHeaders,
    parseCertificateInfo, evaluateTLSSecurity,
    NetworkAnomalyDetector, CORSConfigBuilder,
};
