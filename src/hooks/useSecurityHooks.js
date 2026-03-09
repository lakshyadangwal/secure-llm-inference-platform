/**
 * Custom React Hooks Library for Security Platform
 * Comprehensive collection of reusable hooks for state management,
 * data fetching, form handling, keyboard shortcuts, and more.
 *
 * @module hooks
 * @version 2.0.0
 */

import { useState, useEffect, useRef, useCallback, useMemo, useReducer } from 'react';

// ============================================================================
// Data Fetching Hooks
// ============================================================================

/**
 * Advanced data fetching hook with caching, retry, and pagination.
 * @param {string} url - The URL to fetch from
 * @param {Object} options - Fetch options
 * @returns {Object} Fetch state and controls
 */
export function useFetch(url, options = {}) {
    const {
        method = 'GET',
        headers = {},
        body = null,
        autoFetch = true,
        retryCount = 3,
        retryDelay = 1000,
        timeout = 30000,
        cacheKey = null,
        cacheTTL = 60000,
        transformResponse = null,
        onSuccess = null,
        onError = null,
    } = options;

    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const [retries, setRetries] = useState(0);
    const [lastFetchTime, setLastFetchTime] = useState(null);
    const abortControllerRef = useRef(null);
    const cacheRef = useRef(new Map());
    const mountedRef = useRef(true);

    useEffect(() => {
        mountedRef.current = true;
        return () => { mountedRef.current = false; };
    }, []);

    const fetchData = useCallback(async (overrideUrl = null) => {
        const fetchUrl = overrideUrl || url;
        if (!fetchUrl) return;

        const effectiveCacheKey = cacheKey || fetchUrl;
        const cached = cacheRef.current.get(effectiveCacheKey);
        if (cached && Date.now() - cached.timestamp < cacheTTL) {
            if (mountedRef.current) {
                setData(cached.data);
                setLoading(false);
            }
            return cached.data;
        }

        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
        }
        abortControllerRef.current = new AbortController();

        if (mountedRef.current) {
            setLoading(true);
            setError(null);
        }

        const timeoutId = setTimeout(() => {
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        }, timeout);

        let lastError = null;
        for (let attempt = 0; attempt <= retryCount; attempt++) {
            try {
                const fetchOptions = {
                    method,
                    headers: { 'Content-Type': 'application/json', ...headers },
                    signal: abortControllerRef.current.signal,
                };
                if (body && method !== 'GET') {
                    fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
                }

                const response = await fetch(fetchUrl, fetchOptions);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                let result = await response.json();
                if (transformResponse) {
                    result = transformResponse(result);
                }

                clearTimeout(timeoutId);

                if (mountedRef.current) {
                    setData(result);
                    setLoading(false);
                    setLastFetchTime(Date.now());
                    setRetries(attempt);
                }

                cacheRef.current.set(effectiveCacheKey, { data: result, timestamp: Date.now() });
                if (onSuccess) onSuccess(result);
                return result;
            } catch (err) {
                lastError = err;
                if (err.name === 'AbortError') break;
                if (attempt < retryCount) {
                    await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt)));
                }
            }
        }

        clearTimeout(timeoutId);
        if (mountedRef.current) {
            setError(lastError);
            setLoading(false);
        }
        if (onError) onError(lastError);
        return null;
    }, [url, method, body, retryCount, retryDelay, timeout, cacheKey, cacheTTL, transformResponse, onSuccess, onError, headers]);

    useEffect(() => {
        if (autoFetch && url) {
            fetchData();
        }
        return () => {
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        };
    }, [url, autoFetch, fetchData]);

    const clearCache = useCallback((key = null) => {
        if (key) {
            cacheRef.current.delete(key);
        } else {
            cacheRef.current.clear();
        }
    }, []);

    const refetch = useCallback(() => fetchData(), [fetchData]);

    return {
        data, error, loading, retries, lastFetchTime,
        refetch, clearCache, fetchData,
    };
}

/**
 * Paginated data fetching hook.
 * @param {string} baseUrl - Base URL for pagination
 * @param {Object} options - Pagination options
 * @returns {Object} Paginated data and controls
 */
export function usePagination(baseUrl, options = {}) {
    const {
        pageSize = 20,
        initialPage = 1,
        pageParam = 'page',
        sizeParam = 'pageSize',
    } = options;

    const [page, setPage] = useState(initialPage);
    const [totalPages, setTotalPages] = useState(1);
    const [totalItems, setTotalItems] = useState(0);
    const [allData, setAllData] = useState([]);

    const url = useMemo(() => {
        const separator = baseUrl.includes('?') ? '&' : '?';
        return `${baseUrl}${separator}${pageParam}=${page}&${sizeParam}=${pageSize}`;
    }, [baseUrl, page, pageSize, pageParam, sizeParam]);

    const { data, loading, error, refetch } = useFetch(url, {
        transformResponse: (response) => {
            if (response.totalPages) setTotalPages(response.totalPages);
            if (response.total) setTotalItems(response.total);
            return response.data || response.results || response.items || response;
        },
    });

    useEffect(() => {
        if (data) {
            setAllData(prev => {
                const copy = [...prev];
                copy[page - 1] = data;
                return copy;
            });
        }
    }, [data, page]);

    const nextPage = useCallback(() => {
        if (page < totalPages) setPage(p => p + 1);
    }, [page, totalPages]);

    const prevPage = useCallback(() => {
        if (page > 1) setPage(p => p - 1);
    }, [page]);

    const goToPage = useCallback((p) => {
        if (p >= 1 && p <= totalPages) setPage(p);
    }, [totalPages]);

    return {
        data, loading, error, page, totalPages, totalItems,
        nextPage, prevPage, goToPage, setPage, refetch,
        hasNext: page < totalPages,
        hasPrev: page > 1,
    };
}

// ============================================================================
// Form Hooks
// ============================================================================

/**
 * Comprehensive form management hook with validation.
 * @param {Object} initialValues - Initial form values
 * @param {Object} validationRules - Validation rules per field
 * @param {Function} onSubmit - Submit handler
 * @returns {Object} Form state and handlers
 */
export function useForm(initialValues = {}, validationRules = {}, onSubmit = null) {
    const [values, setValues] = useState(initialValues);
    const [errors, setErrors] = useState({});
    const [touched, setTouched] = useState({});
    const [submitting, setSubmitting] = useState(false);
    const [submitted, setSubmitted] = useState(false);
    const [dirty, setDirty] = useState(false);
    const [submitCount, setSubmitCount] = useState(0);

    const validate = useCallback((fieldName = null) => {
        const newErrors = {};
        const fieldsToValidate = fieldName ? { [fieldName]: validationRules[fieldName] } : validationRules;

        for (const [field, rules] of Object.entries(fieldsToValidate)) {
            if (!rules) continue;
            const value = values[field];

            if (rules.required && (!value || (typeof value === 'string' && !value.trim()))) {
                newErrors[field] = rules.requiredMessage || `${field} is required`;
                continue;
            }
            if (rules.minLength && typeof value === 'string' && value.length < rules.minLength) {
                newErrors[field] = rules.minLengthMessage || `${field} must be at least ${rules.minLength} characters`;
                continue;
            }
            if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) {
                newErrors[field] = rules.maxLengthMessage || `${field} must be at most ${rules.maxLength} characters`;
                continue;
            }
            if (rules.pattern && typeof value === 'string' && !rules.pattern.test(value)) {
                newErrors[field] = rules.patternMessage || `${field} format is invalid`;
                continue;
            }
            if (rules.min !== undefined && Number(value) < rules.min) {
                newErrors[field] = rules.minMessage || `${field} must be at least ${rules.min}`;
                continue;
            }
            if (rules.max !== undefined && Number(value) > rules.max) {
                newErrors[field] = rules.maxMessage || `${field} must be at most ${rules.max}`;
                continue;
            }
            if (rules.validate && typeof rules.validate === 'function') {
                const customError = rules.validate(value, values);
                if (customError) {
                    newErrors[field] = customError;
                    continue;
                }
            }
            if (rules.email && typeof value === 'string') {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(value)) {
                    newErrors[field] = rules.emailMessage || 'Invalid email address';
                    continue;
                }
            }
            if (rules.match && values[rules.match] !== value) {
                newErrors[field] = rules.matchMessage || `${field} does not match ${rules.match}`;
                continue;
            }
        }

        if (fieldName) {
            setErrors(prev => ({ ...prev, ...newErrors, ...(newErrors[fieldName] ? {} : { [fieldName]: undefined }) }));
        } else {
            setErrors(newErrors);
        }
        return newErrors;
    }, [values, validationRules]);

    const handleChange = useCallback((e) => {
        const { name, value, type, checked } = e.target;
        const newValue = type === 'checkbox' ? checked : value;
        setValues(prev => ({ ...prev, [name]: newValue }));
        setDirty(true);
        if (touched[name]) {
            validate(name);
        }
    }, [touched, validate]);

    const handleBlur = useCallback((e) => {
        const { name } = e.target;
        setTouched(prev => ({ ...prev, [name]: true }));
        validate(name);
    }, [validate]);

    const setValue = useCallback((name, value) => {
        setValues(prev => ({ ...prev, [name]: value }));
        setDirty(true);
    }, []);

    const setFieldError = useCallback((name, error) => {
        setErrors(prev => ({ ...prev, [name]: error }));
    }, []);

    const handleSubmit = useCallback(async (e) => {
        if (e) e.preventDefault();
        const validationErrors = validate();
        setTouched(Object.keys(validationRules).reduce((acc, key) => ({ ...acc, [key]: true }), {}));

        if (Object.keys(validationErrors).length > 0) return false;

        setSubmitting(true);
        setSubmitCount(prev => prev + 1);
        try {
            if (onSubmit) await onSubmit(values);
            setSubmitted(true);
            return true;
        } catch (err) {
            if (err.fieldErrors) setErrors(err.fieldErrors);
            return false;
        } finally {
            setSubmitting(false);
        }
    }, [values, validate, validationRules, onSubmit]);

    const reset = useCallback((newValues = null) => {
        setValues(newValues || initialValues);
        setErrors({});
        setTouched({});
        setSubmitting(false);
        setSubmitted(false);
        setDirty(false);
    }, [initialValues]);

    const isValid = useMemo(() => Object.keys(errors).filter(k => errors[k]).length === 0, [errors]);

    return {
        values, errors, touched, submitting, submitted, dirty, submitCount, isValid,
        handleChange, handleBlur, handleSubmit, setValue, setFieldError, reset, validate,
        getFieldProps: (name) => ({
            name, value: values[name] || '', onChange: handleChange, onBlur: handleBlur,
        }),
    };
}

// ============================================================================
// UI State Hooks
// ============================================================================

/**
 * Debounced value hook.
 * @param {*} value - Value to debounce
 * @param {number} delay - Debounce delay in ms
 * @returns {*} Debounced value
 */
export function useDebounce(value, delay = 300) {
    const [debouncedValue, setDebouncedValue] = useState(value);

    useEffect(() => {
        const timer = setTimeout(() => setDebouncedValue(value), delay);
        return () => clearTimeout(timer);
    }, [value, delay]);

    return debouncedValue;
}

/**
 * Throttled callback hook.
 * @param {Function} callback - Function to throttle
 * @param {number} delay - Throttle delay in ms
 * @returns {Function} Throttled function
 */
export function useThrottle(callback, delay = 300) {
    const lastRun = useRef(Date.now());
    const timeoutRef = useRef(null);

    return useCallback((...args) => {
        const now = Date.now();
        if (now - lastRun.current >= delay) {
            lastRun.current = now;
            callback(...args);
        } else {
            if (timeoutRef.current) clearTimeout(timeoutRef.current);
            timeoutRef.current = setTimeout(() => {
                lastRun.current = Date.now();
                callback(...args);
            }, delay - (now - lastRun.current));
        }
    }, [callback, delay]);
}

/**
 * Local storage hook with serialization.
 * @param {string} key - Storage key
 * @param {*} initialValue - Default value
 * @returns {[*, Function, Function]} Value, setter, and remover
 */
export function useLocalStorage(key, initialValue) {
    const [storedValue, setStoredValue] = useState(() => {
        try {
            const item = window.localStorage.getItem(key);
            return item ? JSON.parse(item) : initialValue;
        } catch {
            return initialValue;
        }
    });

    const setValue = useCallback((value) => {
        const valueToStore = value instanceof Function ? value(storedValue) : value;
        setStoredValue(valueToStore);
        try {
            window.localStorage.setItem(key, JSON.stringify(valueToStore));
        } catch (err) {
            console.error('Error saving to localStorage:', err);
        }
    }, [key, storedValue]);

    const remove = useCallback(() => {
        setStoredValue(initialValue);
        window.localStorage.removeItem(key);
    }, [key, initialValue]);

    return [storedValue, setValue, remove];
}

/**
 * Session storage hook.
 * @param {string} key - Storage key
 * @param {*} initialValue - Default value
 * @returns {[*, Function]} Value and setter
 */
export function useSessionStorage(key, initialValue) {
    const [value, setValue] = useState(() => {
        try {
            const item = window.sessionStorage.getItem(key);
            return item ? JSON.parse(item) : initialValue;
        } catch {
            return initialValue;
        }
    });

    const setSessionValue = useCallback((newValue) => {
        const v = newValue instanceof Function ? newValue(value) : newValue;
        setValue(v);
        try { window.sessionStorage.setItem(key, JSON.stringify(v)); } catch { }
    }, [key, value]);

    return [value, setSessionValue];
}

/**
 * Toggle boolean state hook.
 * @param {boolean} initial - Initial state
 * @returns {[boolean, Function, Function, Function]} State and controls
 */
export function useToggle(initial = false) {
    const [state, setState] = useState(initial);
    const toggle = useCallback(() => setState(s => !s), []);
    const setTrue = useCallback(() => setState(true), []);
    const setFalse = useCallback(() => setState(false), []);
    return [state, toggle, setTrue, setFalse];
}

/**
 * Counter hook with increment, decrement, and bounds.
 * @param {number} initial - Initial count
 * @param {Object} options - Counter options
 * @returns {Object} Counter state and controls
 */
export function useCounter(initial = 0, options = {}) {
    const { min = -Infinity, max = Infinity, step = 1 } = options;
    const [count, setCount] = useState(Math.max(min, Math.min(max, initial)));
    const increment = useCallback(() => setCount(c => Math.min(max, c + step)), [max, step]);
    const decrement = useCallback(() => setCount(c => Math.max(min, c - step)), [min, step]);
    const reset = useCallback(() => setCount(initial), [initial]);
    const set = useCallback((v) => setCount(Math.max(min, Math.min(max, v))), [min, max]);
    return { count, increment, decrement, reset, set };
}

// ============================================================================
// Keyboard & Event Hooks
// ============================================================================

/**
 * Keyboard shortcut hook.
 * @param {Object} shortcuts - Map of key combos to handlers
 * @param {Object} options - Options
 */
export function useKeyboardShortcuts(shortcuts, options = {}) {
    const { enabled = true, preventDefault = true, target = null } = options;

    useEffect(() => {
        if (!enabled) return;

        const handler = (e) => {
            for (const [combo, callback] of Object.entries(shortcuts)) {
                const keys = combo.toLowerCase().split('+').map(k => k.trim());
                const key = keys[keys.length - 1];
                const needCtrl = keys.includes('ctrl') || keys.includes('control');
                const needShift = keys.includes('shift');
                const needAlt = keys.includes('alt');
                const needMeta = keys.includes('meta') || keys.includes('cmd');

                if (
                    e.key.toLowerCase() === key &&
                    e.ctrlKey === needCtrl &&
                    e.shiftKey === needShift &&
                    e.altKey === needAlt &&
                    e.metaKey === needMeta
                ) {
                    if (preventDefault) e.preventDefault();
                    callback(e);
                    break;
                }
            }
        };

        const el = target || document;
        el.addEventListener('keydown', handler);
        return () => el.removeEventListener('keydown', handler);
    }, [shortcuts, enabled, preventDefault, target]);
}

/**
 * Click outside hook for modals and dropdowns.
 * @param {Function} handler - Click outside handler
 * @returns {Object} Ref to attach to the target element
 */
export function useClickOutside(handler) {
    const ref = useRef(null);

    useEffect(() => {
        const listener = (e) => {
            if (!ref.current || ref.current.contains(e.target)) return;
            handler(e);
        };
        document.addEventListener('mousedown', listener);
        document.addEventListener('touchstart', listener);
        return () => {
            document.removeEventListener('mousedown', listener);
            document.removeEventListener('touchstart', listener);
        };
    }, [handler]);

    return ref;
}

/**
 * Intersection observer hook for lazy loading and infinite scroll.
 * @param {Object} options - IntersectionObserver options
 * @returns {[Object, boolean]} Ref and isIntersecting state
 */
export function useIntersectionObserver(options = {}) {
    const { threshold = 0, rootMargin = '0px', root = null } = options;
    const ref = useRef(null);
    const [isIntersecting, setIsIntersecting] = useState(false);
    const [entry, setEntry] = useState(null);

    useEffect(() => {
        if (!ref.current) return;
        const observer = new IntersectionObserver(
            ([e]) => { setIsIntersecting(e.isIntersecting); setEntry(e); },
            { threshold, rootMargin, root }
        );
        observer.observe(ref.current);
        return () => observer.disconnect();
    }, [threshold, rootMargin, root]);

    return [ref, isIntersecting, entry];
}

/**
 * Window size hook.
 * @returns {Object} Window dimensions
 */
export function useWindowSize() {
    const [size, setSize] = useState({ width: window.innerWidth, height: window.innerHeight });

    useEffect(() => {
        let timeout;
        const handler = () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                setSize({ width: window.innerWidth, height: window.innerHeight });
            }, 150);
        };
        window.addEventListener('resize', handler);
        return () => { window.removeEventListener('resize', handler); clearTimeout(timeout); };
    }, []);

    return size;
}

/**
 * Media query hook.
 * @param {string} query - CSS media query
 * @returns {boolean} Whether the query matches
 */
export function useMediaQuery(query) {
    const [matches, setMatches] = useState(() => window.matchMedia(query).matches);

    useEffect(() => {
        const mql = window.matchMedia(query);
        const handler = (e) => setMatches(e.matches);
        mql.addEventListener('change', handler);
        setMatches(mql.matches);
        return () => mql.removeEventListener('change', handler);
    }, [query]);

    return matches;
}

// ============================================================================
// Timer & Interval Hooks
// ============================================================================

/**
 * Interval hook.
 * @param {Function} callback - Function to call on each interval
 * @param {number|null} delay - Interval delay in ms (null to stop)
 */
export function useInterval(callback, delay) {
    const savedCallback = useRef(callback);

    useEffect(() => { savedCallback.current = callback; }, [callback]);

    useEffect(() => {
        if (delay === null) return;
        const id = setInterval(() => savedCallback.current(), delay);
        return () => clearInterval(id);
    }, [delay]);
}

/**
 * Countdown timer hook.
 * @param {number} initialSeconds - Starting seconds
 * @param {Object} options - Timer options
 * @returns {Object} Timer state and controls
 */
export function useCountdown(initialSeconds, options = {}) {
    const { autoStart = false, onComplete = null, interval = 1000 } = options;
    const [seconds, setSeconds] = useState(initialSeconds);
    const [isRunning, setIsRunning] = useState(autoStart);

    useInterval(() => {
        setSeconds(s => {
            if (s <= 1) {
                setIsRunning(false);
                if (onComplete) onComplete();
                return 0;
            }
            return s - 1;
        });
    }, isRunning ? interval : null);

    const start = useCallback(() => setIsRunning(true), []);
    const pause = useCallback(() => setIsRunning(false), []);
    const reset = useCallback((newSeconds = null) => {
        setSeconds(newSeconds ?? initialSeconds);
        setIsRunning(false);
    }, [initialSeconds]);

    const formatted = useMemo(() => {
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    }, [seconds]);

    return { seconds, isRunning, formatted, start, pause, reset };
}

/**
 * Stopwatch hook.
 * @returns {Object} Stopwatch state and controls
 */
export function useStopwatch() {
    const [elapsed, setElapsed] = useState(0);
    const [isRunning, setIsRunning] = useState(false);
    const [laps, setLaps] = useState([]);
    const startTimeRef = useRef(null);

    useInterval(() => {
        if (startTimeRef.current) {
            setElapsed(Date.now() - startTimeRef.current);
        }
    }, isRunning ? 10 : null);

    const start = useCallback(() => {
        startTimeRef.current = Date.now() - elapsed;
        setIsRunning(true);
    }, [elapsed]);

    const pause = useCallback(() => setIsRunning(false), []);

    const reset = useCallback(() => {
        setIsRunning(false);
        setElapsed(0);
        setLaps([]);
        startTimeRef.current = null;
    }, []);

    const lap = useCallback(() => {
        setLaps(prev => [...prev, elapsed]);
    }, [elapsed]);

    const formatted = useMemo(() => {
        const ms = elapsed % 1000;
        const s = Math.floor(elapsed / 1000) % 60;
        const m = Math.floor(elapsed / 60000) % 60;
        const h = Math.floor(elapsed / 3600000);
        return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}.${ms.toString().padStart(3, '0')}`;
    }, [elapsed]);

    return { elapsed, isRunning, formatted, laps, start, pause, reset, lap };
}

// ============================================================================
// Clipboard & Copy Hook
// ============================================================================

/**
 * Clipboard hook for copying text.
 * @param {number} resetDelay - Delay before resetting copied state
 * @returns {Object} Copy controls and state
 */
export function useClipboard(resetDelay = 2000) {
    const [copied, setCopied] = useState(false);
    const [error, setError] = useState(null);
    const timeoutRef = useRef(null);

    const copy = useCallback(async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setError(null);
            if (timeoutRef.current) clearTimeout(timeoutRef.current);
            timeoutRef.current = setTimeout(() => setCopied(false), resetDelay);
            return true;
        } catch (err) {
            setError(err);
            setCopied(false);
            return false;
        }
    }, [resetDelay]);

    useEffect(() => {
        return () => { if (timeoutRef.current) clearTimeout(timeoutRef.current); };
    }, []);

    return { copy, copied, error };
}

// ============================================================================
// Animation Hooks
// ============================================================================

/**
 * Animated value hook using requestAnimationFrame.
 * @param {number} targetValue - Target value to animate to
 * @param {Object} options - Animation options
 * @returns {number} Current animated value
 */
export function useAnimatedValue(targetValue, options = {}) {
    const { duration = 300, easing = 'easeOutCubic' } = options;
    const [value, setValue] = useState(targetValue);
    const animationRef = useRef(null);
    const startRef = useRef({ value: targetValue, time: 0 });

    const easingFunctions = useMemo(() => ({
        linear: t => t,
        easeInCubic: t => t * t * t,
        easeOutCubic: t => 1 - Math.pow(1 - t, 3),
        easeInOutCubic: t => t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2,
        easeOutElastic: t => {
            if (t === 0 || t === 1) return t;
            return Math.pow(2, -10 * t) * Math.sin((t - 0.075) * (2 * Math.PI) / 0.3) + 1;
        },
        easeOutBounce: t => {
            if (t < 1 / 2.75) return 7.5625 * t * t;
            if (t < 2 / 2.75) return 7.5625 * (t -= 1.5 / 2.75) * t + 0.75;
            if (t < 2.5 / 2.75) return 7.5625 * (t -= 2.25 / 2.75) * t + 0.9375;
            return 7.5625 * (t -= 2.625 / 2.75) * t + 0.984375;
        },
    }), []);

    useEffect(() => {
        startRef.current = { value: value, time: performance.now() };
        const easeFn = easingFunctions[easing] || easingFunctions.easeOutCubic;

        const animate = (currentTime) => {
            const elapsed = currentTime - startRef.current.time;
            const progress = Math.min(elapsed / duration, 1);
            const easedProgress = easeFn(progress);
            const newValue = startRef.current.value + (targetValue - startRef.current.value) * easedProgress;
            setValue(newValue);
            if (progress < 1) {
                animationRef.current = requestAnimationFrame(animate);
            }
        };

        animationRef.current = requestAnimationFrame(animate);
        return () => {
            if (animationRef.current) cancelAnimationFrame(animationRef.current);
        };
    }, [targetValue, duration, easing, easingFunctions]);

    return value;
}

/**
 * Previous value hook.
 * @param {*} value - Current value
 * @returns {*} Previous value
 */
export function usePrevious(value) {
    const ref = useRef();
    useEffect(() => { ref.current = value; });
    return ref.current;
}

// ============================================================================
// Network Hooks
// ============================================================================

/**
 * Online/offline status hook.
 * @returns {boolean} Whether the browser is online
 */
export function useOnline() {
    const [online, setOnline] = useState(navigator.onLine);

    useEffect(() => {
        const onOnline = () => setOnline(true);
        const onOffline = () => setOnline(false);
        window.addEventListener('online', onOnline);
        window.addEventListener('offline', onOffline);
        return () => {
            window.removeEventListener('online', onOnline);
            window.removeEventListener('offline', onOffline);
        };
    }, []);

    return online;
}

/**
 * WebSocket hook.
 * @param {string} url - WebSocket URL
 * @param {Object} options - WebSocket options
 * @returns {Object} WebSocket state and controls
 */
export function useWebSocket(url, options = {}) {
    const { autoConnect = true, reconnect = true, reconnectInterval = 3000, maxReconnects = 10, onMessage = null, onOpen = null, onClose = null, onError = null } = options;
    const [status, setStatus] = useState('disconnected');
    const [lastMessage, setLastMessage] = useState(null);
    const [messageHistory, setMessageHistory] = useState([]);
    const wsRef = useRef(null);
    const reconnectCount = useRef(0);
    const reconnectTimer = useRef(null);

    const connect = useCallback(() => {
        if (!url) return;
        try {
            const ws = new WebSocket(url);
            wsRef.current = ws;
            setStatus('connecting');

            ws.onopen = (e) => {
                setStatus('connected');
                reconnectCount.current = 0;
                if (onOpen) onOpen(e);
            };

            ws.onmessage = (e) => {
                let data;
                try { data = JSON.parse(e.data); } catch { data = e.data; }
                setLastMessage(data);
                setMessageHistory(prev => [...prev.slice(-99), data]);
                if (onMessage) onMessage(data, e);
            };

            ws.onclose = (e) => {
                setStatus('disconnected');
                if (onClose) onClose(e);
                if (reconnect && reconnectCount.current < maxReconnects && !e.wasClean) {
                    reconnectTimer.current = setTimeout(() => {
                        reconnectCount.current++;
                        connect();
                    }, reconnectInterval);
                }
            };

            ws.onerror = (e) => {
                setStatus('error');
                if (onError) onError(e);
            };
        } catch (err) {
            setStatus('error');
            if (onError) onError(err);
        }
    }, [url, reconnect, reconnectInterval, maxReconnects, onMessage, onOpen, onClose, onError]);

    const disconnect = useCallback(() => {
        if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
        if (wsRef.current) wsRef.current.close(1000, 'Client disconnect');
    }, []);

    const send = useCallback((data) => {
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data));
            return true;
        }
        return false;
    }, []);

    useEffect(() => {
        if (autoConnect) connect();
        return () => { disconnect(); };
    }, [autoConnect, connect, disconnect]);

    return { status, lastMessage, messageHistory, send, connect, disconnect };
}

// ============================================================================
// Export all hooks
// ============================================================================

export default {
    useFetch, usePagination, useForm, useDebounce, useThrottle,
    useLocalStorage, useSessionStorage, useToggle, useCounter,
    useKeyboardShortcuts, useClickOutside, useIntersectionObserver,
    useWindowSize, useMediaQuery, useInterval, useCountdown, useStopwatch,
    useClipboard, useAnimatedValue, usePrevious, useOnline, useWebSocket,
};
