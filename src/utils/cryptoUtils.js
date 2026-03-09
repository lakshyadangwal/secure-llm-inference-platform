/**
 * Cryptographic Utilities Module
 * Client-side crypto operations for Neuro-Sentry Defense Platform
 * @module cryptoUtils
 * @version 2.0.0
 */

const ALGORITHM_CONFIG = {
    AES_GCM: { name: 'AES-GCM', length: 256, ivLength: 12, tagLength: 128 },
    AES_CBC: { name: 'AES-CBC', length: 256, ivLength: 16 },
    RSA_OAEP: { name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    ECDSA: { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' },
    ECDH: { name: 'ECDH', namedCurve: 'P-384' },
    HMAC: { name: 'HMAC', hash: 'SHA-256', length: 256 },
    PBKDF2: { name: 'PBKDF2', iterations: 600000, hash: 'SHA-256', saltLength: 32 },
    HKDF: { name: 'HKDF', hash: 'SHA-256', infoPrefix: 'neuro-sentry-v2' },
};

const KEY_USAGES = {
    ENCRYPT_DECRYPT: ['encrypt', 'decrypt'],
    SIGN_VERIFY: ['sign', 'verify'],
    WRAP_UNWRAP: ['wrapKey', 'unwrapKey'],
    DERIVE: ['deriveBits', 'deriveKey'],
};

export function stringToBuffer(str) {
    return new TextEncoder().encode(str).buffer;
}

export function bufferToString(buffer) {
    return new TextDecoder('utf-8').decode(buffer);
}

export function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBuffer(hex) {
    const clean = hex.replace(/\s/g, '');
    if (clean.length % 2 !== 0) throw new Error('Invalid hex string: odd length');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
        const byte = parseInt(clean.substr(i, 2), 16);
        if (isNaN(byte)) throw new Error(`Invalid hex character at position ${i}`);
        bytes[i / 2] = byte;
    }
    return bytes.buffer;
}

export function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

export function base64ToBuffer(base64) {
    const binary = atob(base64.replace(/[\s\n\r]/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

export function bufferToBase64Url(buffer) {
    return bufferToBase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBuffer(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    return base64ToBuffer(b64);
}

export function concatBuffers(...buffers) {
    const total = buffers.reduce((s, b) => s + b.byteLength, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const buf of buffers) { result.set(new Uint8Array(buf), offset); offset += buf.byteLength; }
    return result.buffer;
}

export function constantTimeEqual(a, b) {
    const va = new Uint8Array(a), vb = new Uint8Array(b);
    if (va.length !== vb.length) return false;
    let r = 0;
    for (let i = 0; i < va.length; i++) r |= va[i] ^ vb[i];
    return r === 0;
}

export function getRandomBytes(length) {
    if (length <= 0 || length > 65536) throw new RangeError('Length must be between 1 and 65536');
    const buf = new Uint8Array(length);
    crypto.getRandomValues(buf);
    return buf.buffer;
}

export function getRandomHex(byteLength = 32) {
    return bufferToHex(getRandomBytes(byteLength));
}

export function generateUUIDv4() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const h = bufferToHex(bytes.buffer);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export function generateSecureToken(length = 48) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => chars[b % chars.length]).join('');
}

export function getSecureRandomInt(min, max) {
    if (min >= max) throw new RangeError('min must be less than max');
    const range = max - min;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8) || 1;
    const maxValid = Math.pow(256, bytesNeeded);
    const cutoff = maxValid - (maxValid % range);
    let value;
    do {
        const b = new Uint8Array(bytesNeeded);
        crypto.getRandomValues(b);
        value = 0;
        for (let i = 0; i < bytesNeeded; i++) value = (value << 8) | b[i];
    } while (value >= cutoff);
    return min + (value % range);
}

export async function sha256(data) {
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    return bufferToHex(await crypto.subtle.digest('SHA-256', buf));
}

export async function sha384(data) {
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    return bufferToHex(await crypto.subtle.digest('SHA-384', buf));
}

export async function sha512(data) {
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    return bufferToHex(await crypto.subtle.digest('SHA-512', buf));
}

export async function multiHash(data) {
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    const [h256, h384, h512] = await Promise.all([
        crypto.subtle.digest('SHA-256', buf),
        crypto.subtle.digest('SHA-384', buf),
        crypto.subtle.digest('SHA-512', buf),
    ]);
    return { sha256: bufferToHex(h256), sha384: bufferToHex(h384), sha512: bufferToHex(h512), timestamp: Date.now() };
}

export async function objectFingerprint(obj, algo = 'SHA-256') {
    const normalized = JSON.stringify(obj, Object.keys(obj).sort());
    return bufferToHex(await crypto.subtle.digest(algo, stringToBuffer(normalized)));
}

export async function createHmacKey(keyMaterial, hash = 'SHA-256') {
    const buf = typeof keyMaterial === 'string' ? stringToBuffer(keyMaterial) : keyMaterial;
    return crypto.subtle.importKey('raw', buf, { name: 'HMAC', hash: { name: hash } }, false, ['sign', 'verify']);
}

export async function generateHmacKey(hash = 'SHA-256', extractable = true) {
    return crypto.subtle.generateKey({ name: 'HMAC', hash: { name: hash } }, extractable, ['sign', 'verify']);
}

export async function hmacSign(key, data) {
    const ck = typeof key === 'string' ? await createHmacKey(key) : key;
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    return bufferToHex(await crypto.subtle.sign('HMAC', ck, buf));
}

export async function hmacVerify(key, data, signature) {
    const ck = typeof key === 'string' ? await createHmacKey(key) : key;
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    return crypto.subtle.verify('HMAC', ck, hexToBuffer(signature), buf);
}

export async function generateAesKey(length = 256, mode = 'AES-GCM', extractable = true) {
    return crypto.subtle.generateKey({ name: mode, length }, extractable, KEY_USAGES.ENCRYPT_DECRYPT);
}

export async function importAesKey(keyBytes, mode = 'AES-GCM', extractable = false) {
    return crypto.subtle.importKey('raw', keyBytes, { name: mode }, extractable, KEY_USAGES.ENCRYPT_DECRYPT);
}

export async function aesGcmEncrypt(key, plaintext, additionalData = null) {
    const iv = getRandomBytes(ALGORITHM_CONFIG.AES_GCM.ivLength);
    const data = typeof plaintext === 'string' ? stringToBuffer(plaintext) : plaintext;
    const algo = { name: 'AES-GCM', iv: new Uint8Array(iv), tagLength: ALGORITHM_CONFIG.AES_GCM.tagLength };
    if (additionalData) algo.additionalData = additionalData;
    const ct = await crypto.subtle.encrypt(algo, key, data);
    return { iv: bufferToBase64(iv), ciphertext: bufferToBase64(ct), algorithm: 'AES-256-GCM', timestamp: Date.now() };
}

export async function aesGcmDecrypt(key, encData, additionalData = null) {
    const iv = base64ToBuffer(encData.iv);
    const ct = base64ToBuffer(encData.ciphertext);
    const algo = { name: 'AES-GCM', iv: new Uint8Array(iv), tagLength: 128 };
    if (additionalData) algo.additionalData = additionalData;
    return bufferToString(await crypto.subtle.decrypt(algo, key, ct));
}

export async function deriveKeyPBKDF2(password, salt = null, iterations = 600000, keyLength = 256, hash = 'SHA-256') {
    const actualSalt = salt || getRandomBytes(32);
    const baseKey = await crypto.subtle.importKey('raw', stringToBuffer(password), 'PBKDF2', false, ['deriveKey']);
    const derived = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: new Uint8Array(actualSalt), iterations, hash },
        baseKey, { name: 'AES-GCM', length: keyLength }, true, KEY_USAGES.ENCRYPT_DECRYPT
    );
    return { key: derived, salt: bufferToBase64(actualSalt), iterations, hash, keyLength };
}

export async function deriveKeyHKDF(ikm, salt, info, keyLength = 256) {
    const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(salt), info: new Uint8Array(stringToBuffer(`neuro-sentry-v2:${info}`)) },
        baseKey, { name: 'AES-GCM', length: keyLength }, true, KEY_USAGES.ENCRYPT_DECRYPT
    );
}

export async function generateRsaKeyPair(modulusLength = 4096) {
    return crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, KEY_USAGES.ENCRYPT_DECRYPT
    );
}

export async function rsaEncrypt(publicKey, plaintext) {
    const data = typeof plaintext === 'string' ? stringToBuffer(plaintext) : plaintext;
    return bufferToBase64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data));
}

export async function rsaDecrypt(privateKey, ciphertext) {
    return bufferToString(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, base64ToBuffer(ciphertext)));
}

export async function generateEcdsaKeyPair(namedCurve = 'P-384') {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, KEY_USAGES.SIGN_VERIFY);
}

export async function ecdsaSign(privateKey, data, hash = 'SHA-384') {
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    return bufferToBase64(await crypto.subtle.sign({ name: 'ECDSA', hash: { name: hash } }, privateKey, buf));
}

export async function ecdsaVerify(publicKey, data, signature, hash = 'SHA-384') {
    const buf = typeof data === 'string' ? stringToBuffer(data) : data;
    return crypto.subtle.verify({ name: 'ECDSA', hash: { name: hash } }, publicKey, base64ToBuffer(signature), buf);
}

export async function generateEcdhKeyPair(namedCurve = 'P-384') {
    return crypto.subtle.generateKey({ name: 'ECDH', namedCurve }, true, KEY_USAGES.DERIVE);
}

export async function ecdhDeriveKey(privateKey, publicKey, keyLength = 256) {
    return crypto.subtle.deriveKey({ name: 'ECDH', public: publicKey }, privateKey, { name: 'AES-GCM', length: keyLength }, true, KEY_USAGES.ENCRYPT_DECRYPT);
}

export async function encryptWithPassword(password, plaintext) {
    const { key, salt, iterations, hash } = await deriveKeyPBKDF2(password);
    const encrypted = await aesGcmEncrypt(key, plaintext);
    return { ...encrypted, salt, iterations, hash, version: 2, createdAt: new Date().toISOString() };
}

export async function decryptWithPassword(password, pkg) {
    const { key } = await deriveKeyPBKDF2(password, base64ToBuffer(pkg.salt), pkg.iterations, 256, pkg.hash);
    return aesGcmDecrypt(key, pkg);
}

export async function secureStore(storageKey, password, data) {
    const encrypted = await encryptWithPassword(password, JSON.stringify(data));
    localStorage.setItem(storageKey, JSON.stringify(encrypted));
}

export async function secureRetrieve(storageKey, password) {
    const stored = localStorage.getItem(storageKey);
    if (!stored) return null;
    return JSON.parse(await decryptWithPassword(password, JSON.parse(stored)));
}

export function secureErase(storageKey) {
    const existing = localStorage.getItem(storageKey);
    if (existing) { localStorage.setItem(storageKey, getRandomHex(existing.length)); localStorage.removeItem(storageKey); }
}

export async function generateSriHash(content, algorithm = 'sha384') {
    const map = { sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
    const hash = await crypto.subtle.digest(map[algorithm], stringToBuffer(content));
    return `${algorithm}-${bufferToBase64(hash)}`;
}

export function generateCspNonce() { return bufferToBase64(getRandomBytes(16)); }

export const CryptoConfig = ALGORITHM_CONFIG;

export default {
    stringToBuffer, bufferToString, bufferToHex, hexToBuffer, bufferToBase64, base64ToBuffer,
    bufferToBase64Url, base64UrlToBuffer, concatBuffers, constantTimeEqual, getRandomBytes,
    getRandomHex, generateUUIDv4, generateSecureToken, getSecureRandomInt, sha256, sha384,
    sha512, multiHash, objectFingerprint, createHmacKey, generateHmacKey, hmacSign, hmacVerify,
    generateAesKey, importAesKey, aesGcmEncrypt, aesGcmDecrypt, deriveKeyPBKDF2, deriveKeyHKDF,
    generateRsaKeyPair, rsaEncrypt, rsaDecrypt, generateEcdsaKeyPair, ecdsaSign, ecdsaVerify,
    generateEcdhKeyPair, ecdhDeriveKey, encryptWithPassword, decryptWithPassword,
    secureStore, secureRetrieve, secureErase, generateSriHash, generateCspNonce, CryptoConfig,
};
