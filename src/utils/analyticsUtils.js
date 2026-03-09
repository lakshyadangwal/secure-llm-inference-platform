/**
 * Security Analytics Dashboard Utilities
 * Comprehensive charting data transformers, metric calculators,
 * trend analyzers, and dashboard state management utilities.
 *
 * @module analyticsUtils
 * @version 2.0.0
 */

// ============================================================================
// Time Utilities
// ============================================================================

/**
 * Format milliseconds to human-readable duration.
 * @param {number} ms - Duration in milliseconds
 * @returns {string} Formatted duration
 */
export function formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
    const hours = Math.floor(ms / 3600000);
    const minutes = Math.floor((ms % 3600000) / 60000);
    return `${hours}h ${minutes}m`;
}

/**
 * Format number with appropriate suffix (K, M, B).
 * @param {number} num - Number to format
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted number
 */
export function formatNumber(num, decimals = 1) {
    if (num === null || num === undefined) return '0';
    if (num < 1000) return num.toString();
    if (num < 1000000) return (num / 1000).toFixed(decimals) + 'K';
    if (num < 1000000000) return (num / 1000000).toFixed(decimals) + 'M';
    return (num / 1000000000).toFixed(decimals) + 'B';
}

/**
 * Format bytes to human-readable size.
 * @param {number} bytes - Byte count
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted size
 */
export function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

/**
 * Format percentage with optional sign.
 * @param {number} value - Percentage value
 * @param {boolean} showSign - Whether to show + sign for positive
 * @returns {string} Formatted percentage
 */
export function formatPercentage(value, showSign = false) {
    const formatted = value.toFixed(1) + '%';
    if (showSign && value > 0) return '+' + formatted;
    return formatted;
}

/**
 * Get relative time string (e.g., "2 hours ago").
 * @param {Date|number} date - The date to compare
 * @returns {string} Relative time string
 */
export function getRelativeTime(date) {
    const now = Date.now();
    const then = date instanceof Date ? date.getTime() : date;
    const diff = now - then;

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const weeks = Math.floor(days / 7);
    const months = Math.floor(days / 30);

    if (seconds < 60) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    if (weeks < 5) return `${weeks}w ago`;
    return `${months}mo ago`;
}

/**
 * Generate time series buckets for a given range.
 * @param {number} startTime - Start timestamp
 * @param {number} endTime - End timestamp
 * @param {string} interval - Bucket interval ('minute', 'hour', 'day', 'week', 'month')
 * @returns {Array} Array of time buckets
 */
export function generateTimeBuckets(startTime, endTime, interval = 'hour') {
    const intervals = {
        minute: 60000,
        hour: 3600000,
        day: 86400000,
        week: 604800000,
        month: 2592000000,
    };

    const step = intervals[interval] || intervals.hour;
    const buckets = [];
    let current = Math.floor(startTime / step) * step;

    while (current <= endTime) {
        buckets.push({
            timestamp: current,
            date: new Date(current).toISOString(),
            label: formatBucketLabel(current, interval),
        });
        current += step;
    }

    return buckets;
}

/**
 * Format bucket label based on interval.
 * @param {number} timestamp - Timestamp to format
 * @param {string} interval - Interval type
 * @returns {string} Formatted label
 */
function formatBucketLabel(timestamp, interval) {
    const date = new Date(timestamp);
    switch (interval) {
        case 'minute': return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        case 'hour': return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        case 'day': return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        case 'week': return `W${getWeekNumber(date)}`;
        case 'month': return date.toLocaleDateString([], { month: 'short', year: '2-digit' });
        default: return date.toISOString();
    }
}

/**
 * Get ISO week number.
 * @param {Date} date - The date
 * @returns {number} Week number
 */
function getWeekNumber(date) {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    const dayNum = d.getUTCDay() || 7;
    d.setUTCDate(d.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
}

// ============================================================================
// Statistical Functions
// ============================================================================

/**
 * Calculate descriptive statistics for an array of numbers.
 * @param {number[]} values - Array of numeric values
 * @returns {Object} Statistical summary
 */
export function calculateStats(values) {
    if (!values || values.length === 0) {
        return { count: 0, mean: 0, median: 0, std: 0, min: 0, max: 0, sum: 0, variance: 0, q1: 0, q3: 0, iqr: 0, skewness: 0, kurtosis: 0 };
    }

    const sorted = [...values].sort((a, b) => a - b);
    const n = sorted.length;
    const sum = sorted.reduce((s, v) => s + v, 0);
    const mean = sum / n;
    const variance = sorted.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / n;
    const std = Math.sqrt(variance);
    const median = n % 2 === 0 ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2 : sorted[Math.floor(n / 2)];
    const q1 = sorted[Math.floor(n * 0.25)];
    const q3 = sorted[Math.floor(n * 0.75)];
    const iqr = q3 - q1;

    let skewness = 0;
    let kurtosis = 0;
    if (std > 0 && n >= 3) {
        skewness = sorted.reduce((s, v) => s + Math.pow((v - mean) / std, 3), 0) / n;
        kurtosis = sorted.reduce((s, v) => s + Math.pow((v - mean) / std, 4), 0) / n - 3;
    }

    return {
        count: n, mean: round(mean, 4), median: round(median, 4), std: round(std, 4),
        min: sorted[0], max: sorted[n - 1], sum: round(sum, 4), variance: round(variance, 4),
        q1: round(q1, 4), q3: round(q3, 4), iqr: round(iqr, 4),
        skewness: round(skewness, 4), kurtosis: round(kurtosis, 4),
        range: round(sorted[n - 1] - sorted[0], 4),
        cv: mean !== 0 ? round(std / Math.abs(mean), 4) : 0,
    };
}

/**
 * Calculate percentile value.
 * @param {number[]} values - Sorted array of values
 * @param {number} p - Percentile (0-100)
 * @returns {number} Percentile value
 */
export function percentile(values, p) {
    const sorted = [...values].sort((a, b) => a - b);
    const idx = (p / 100) * (sorted.length - 1);
    const lower = Math.floor(idx);
    const upper = Math.ceil(idx);
    if (lower === upper) return sorted[lower];
    return sorted[lower] + (sorted[upper] - sorted[lower]) * (idx - lower);
}

/**
 * Calculate moving average.
 * @param {number[]} values - Array of values
 * @param {number} window - Window size
 * @returns {number[]} Moving averages
 */
export function movingAverage(values, window = 5) {
    const result = [];
    for (let i = 0; i < values.length; i++) {
        const start = Math.max(0, i - window + 1);
        const windowValues = values.slice(start, i + 1);
        result.push(windowValues.reduce((s, v) => s + v, 0) / windowValues.length);
    }
    return result;
}

/**
 * Calculate exponential moving average.
 * @param {number[]} values - Array of values
 * @param {number} alpha - Smoothing factor (0-1)
 * @returns {number[]} EMA values
 */
export function exponentialMovingAverage(values, alpha = 0.3) {
    if (!values.length) return [];
    const result = [values[0]];
    for (let i = 1; i < values.length; i++) {
        result.push(alpha * values[i] + (1 - alpha) * result[i - 1]);
    }
    return result;
}

/**
 * Detect outliers using IQR method.
 * @param {number[]} values - Array of values
 * @param {number} multiplier - IQR multiplier (default: 1.5)
 * @returns {Object} Outlier information
 */
export function detectOutliers(values, multiplier = 1.5) {
    const stats = calculateStats(values);
    const lowerBound = stats.q1 - multiplier * stats.iqr;
    const upperBound = stats.q3 + multiplier * stats.iqr;

    const outliers = [];
    const inliers = [];
    values.forEach((v, i) => {
        if (v < lowerBound || v > upperBound) {
            outliers.push({ value: v, index: i, direction: v < lowerBound ? 'low' : 'high' });
        } else {
            inliers.push(v);
        }
    });

    return {
        outliers, outlierCount: outliers.length, outlierPercentage: round((outliers.length / values.length) * 100, 2),
        bounds: { lower: round(lowerBound, 4), upper: round(upperBound, 4) },
        inlierStats: calculateStats(inliers),
    };
}

/**
 * Calculate correlation coefficient between two arrays.
 * @param {number[]} x - First array
 * @param {number[]} y - Second array
 * @returns {number} Pearson correlation coefficient
 */
export function correlation(x, y) {
    const n = Math.min(x.length, y.length);
    if (n < 2) return 0;
    const xMean = x.slice(0, n).reduce((s, v) => s + v, 0) / n;
    const yMean = y.slice(0, n).reduce((s, v) => s + v, 0) / n;
    let numerator = 0, denomX = 0, denomY = 0;
    for (let i = 0; i < n; i++) {
        const dx = x[i] - xMean;
        const dy = y[i] - yMean;
        numerator += dx * dy;
        denomX += dx * dx;
        denomY += dy * dy;
    }
    const denom = Math.sqrt(denomX * denomY);
    return denom === 0 ? 0 : round(numerator / denom, 4);
}

/**
 * Simple linear regression.
 * @param {number[]} x - Independent variable
 * @param {number[]} y - Dependent variable
 * @returns {Object} Regression results
 */
export function linearRegression(x, y) {
    const n = Math.min(x.length, y.length);
    if (n < 2) return { slope: 0, intercept: 0, rSquared: 0 };
    const xMean = x.reduce((s, v) => s + v, 0) / n;
    const yMean = y.reduce((s, v) => s + v, 0) / n;
    let ssXY = 0, ssXX = 0;
    for (let i = 0; i < n; i++) {
        ssXY += (x[i] - xMean) * (y[i] - yMean);
        ssXX += (x[i] - xMean) * (x[i] - xMean);
    }
    const slope = ssXX !== 0 ? ssXY / ssXX : 0;
    const intercept = yMean - slope * xMean;
    const predicted = x.map(xi => slope * xi + intercept);
    const ssRes = y.reduce((s, yi, i) => s + Math.pow(yi - predicted[i], 2), 0);
    const ssTot = y.reduce((s, yi) => s + Math.pow(yi - yMean, 2), 0);
    const rSquared = ssTot !== 0 ? 1 - ssRes / ssTot : 0;

    return { slope: round(slope, 6), intercept: round(intercept, 4), rSquared: round(rSquared, 4), predicted };
}

// ============================================================================
// Chart Data Transformers
// ============================================================================

/**
 * Transform raw events into time series data for charts.
 * @param {Array} events - Array of event objects with timestamp
 * @param {string} interval - Time interval
 * @param {string} valueField - Field to aggregate
 * @param {string} aggregation - Aggregation method
 * @returns {Array} Chart-ready data
 */
export function eventsToTimeSeries(events, interval = 'hour', valueField = null, aggregation = 'count') {
    if (!events || events.length === 0) return [];
    const timestamps = events.map(e => e.timestamp || e.created_at || e.time);
    const minTime = Math.min(...timestamps);
    const maxTime = Math.max(...timestamps);
    const buckets = generateTimeBuckets(minTime, maxTime, interval);
    const intervals_map = { minute: 60000, hour: 3600000, day: 86400000, week: 604800000, month: 2592000000 };
    const step = intervals_map[interval] || intervals_map.hour;

    return buckets.map(bucket => {
        const bucketEvents = events.filter(e => {
            const ts = e.timestamp || e.created_at || e.time;
            return ts >= bucket.timestamp && ts < bucket.timestamp + step;
        });

        let value;
        switch (aggregation) {
            case 'count': value = bucketEvents.length; break;
            case 'sum': value = valueField ? bucketEvents.reduce((s, e) => s + (e[valueField] || 0), 0) : bucketEvents.length; break;
            case 'avg': value = valueField && bucketEvents.length ? bucketEvents.reduce((s, e) => s + (e[valueField] || 0), 0) / bucketEvents.length : 0; break;
            case 'max': value = valueField && bucketEvents.length ? Math.max(...bucketEvents.map(e => e[valueField] || 0)) : 0; break;
            case 'min': value = valueField && bucketEvents.length ? Math.min(...bucketEvents.map(e => e[valueField] || 0)) : 0; break;
            default: value = bucketEvents.length;
        }

        return { ...bucket, value: round(value, 2), eventCount: bucketEvents.length };
    });
}

/**
 * Group events by a categorical field for pie/donut charts.
 * @param {Array} events - Array of event objects
 * @param {string} groupField - Field to group by
 * @param {number} maxGroups - Maximum number of groups (rest go to "Other")
 * @returns {Array} Chart-ready grouped data
 */
export function groupByCategory(events, groupField, maxGroups = 10) {
    const groups = {};
    events.forEach(e => {
        const key = e[groupField] || 'unknown';
        groups[key] = (groups[key] || 0) + 1;
    });

    const sorted = Object.entries(groups).sort((a, b) => b[1] - a[1]);
    const total = events.length;
    const result = [];
    let otherCount = 0;

    sorted.forEach(([key, count], idx) => {
        if (idx < maxGroups) {
            result.push({ name: key, value: count, percentage: round((count / total) * 100, 1) });
        } else {
            otherCount += count;
        }
    });

    if (otherCount > 0) {
        result.push({ name: 'Other', value: otherCount, percentage: round((otherCount / total) * 100, 1) });
    }

    return result;
}

/**
 * Create a heatmap data structure from events.
 * @param {Array} events - Array of event objects
 * @param {string} xField - X axis field
 * @param {string} yField - Y axis field
 * @returns {Object} Heatmap data
 */
export function createHeatmapData(events, xField = 'hour', yField = 'dayOfWeek') {
    const matrix = {};
    const xValues = new Set();
    const yValues = new Set();

    events.forEach(e => {
        const date = new Date(e.timestamp || e.created_at);
        let x, y;

        if (xField === 'hour') x = date.getHours();
        else if (xField === 'day') x = date.getDate();
        else x = e[xField];

        if (yField === 'dayOfWeek') y = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][date.getDay()];
        else if (yField === 'month') y = date.toLocaleString('default', { month: 'short' });
        else y = e[yField];

        xValues.add(x);
        yValues.add(y);
        const key = `${x}-${y}`;
        matrix[key] = (matrix[key] || 0) + 1;
    });

    const data = [];
    xValues.forEach(x => {
        yValues.forEach(y => {
            data.push({ x, y, value: matrix[`${x}-${y}`] || 0 });
        });
    });

    const values = data.map(d => d.value);
    return {
        data,
        xLabels: [...xValues].sort(),
        yLabels: [...yValues],
        min: Math.min(...values),
        max: Math.max(...values),
        total: values.reduce((s, v) => s + v, 0),
    };
}

// ============================================================================
// Trend Analysis
// ============================================================================

/**
 * Detect trends and calculate change rates.
 * @param {number[]} values - Time-ordered values
 * @param {number[]} previousValues - Previous period values for comparison
 * @returns {Object} Trend analysis
 */
export function analyzeTrend(values, previousValues = null) {
    if (!values || values.length < 2) {
        return { trend: 'insufficient_data', change: 0, changePercent: 0 };
    }

    const regression = linearRegression(
        values.map((_, i) => i),
        values
    );

    let trend = 'stable';
    if (regression.slope > 0.01 && regression.rSquared > 0.2) trend = 'increasing';
    else if (regression.slope < -0.01 && regression.rSquared > 0.2) trend = 'decreasing';

    const current = values.slice(-Math.ceil(values.length / 2));
    const previous = values.slice(0, Math.floor(values.length / 2));
    const currentAvg = current.reduce((s, v) => s + v, 0) / current.length;
    const previousAvg = previous.reduce((s, v) => s + v, 0) / previous.length;
    const change = currentAvg - previousAvg;
    const changePercent = previousAvg !== 0 ? (change / previousAvg) * 100 : 0;

    let periodChange = null;
    if (previousValues && previousValues.length > 0) {
        const prevPeriodAvg = previousValues.reduce((s, v) => s + v, 0) / previousValues.length;
        periodChange = {
            change: round(currentAvg - prevPeriodAvg, 4),
            changePercent: prevPeriodAvg !== 0 ? round(((currentAvg - prevPeriodAvg) / prevPeriodAvg) * 100, 2) : 0,
        };
    }

    return {
        trend,
        slope: regression.slope,
        rSquared: regression.rSquared,
        change: round(change, 4),
        changePercent: round(changePercent, 2),
        currentAvg: round(currentAvg, 4),
        previousAvg: round(previousAvg, 4),
        periodChange,
        volatility: calculateStats(values).cv,
    };
}

/**
 * Forecast future values using simple exponential smoothing.
 * @param {number[]} values - Historical values
 * @param {number} periods - Number of periods to forecast
 * @param {number} alpha - Smoothing factor
 * @returns {Object} Forecast results
 */
export function forecast(values, periods = 5, alpha = 0.3) {
    if (!values || values.length < 3) return { forecast: [], confidence: 0 };
    const smoothed = exponentialMovingAverage(values, alpha);
    const lastSmoothed = smoothed[smoothed.length - 1];
    const trend = values.length >= 5
        ? (smoothed[smoothed.length - 1] - smoothed[smoothed.length - 5]) / 4
        : 0;
    const residuals = values.map((v, i) => Math.abs(v - smoothed[i]));
    const avgResidual = residuals.reduce((s, v) => s + v, 0) / residuals.length;
    const forecastValues = [];

    for (let i = 1; i <= periods; i++) {
        const point = lastSmoothed + trend * i;
        forecastValues.push({
            period: i,
            value: round(point, 4),
            lower: round(point - avgResidual * 1.96 * Math.sqrt(i), 4),
            upper: round(point + avgResidual * 1.96 * Math.sqrt(i), 4),
        });
    }

    return {
        forecast: forecastValues,
        trend: round(trend, 6),
        lastSmoothed: round(lastSmoothed, 4),
        avgResidual: round(avgResidual, 4),
        confidence: round(Math.max(0, 1 - avgResidual / Math.abs(lastSmoothed || 1)), 3),
    };
}

// ============================================================================
// Dashboard Metric Calculators
// ============================================================================

/**
 * Calculate key security metrics from event data.
 * @param {Array} events - Array of security events
 * @param {number} timeWindowMs - Time window for recent metrics
 * @returns {Object} Dashboard metrics
 */
export function calculateSecurityMetrics(events, timeWindowMs = 3600000) {
    const now = Date.now();
    const recentEvents = events.filter(e => now - (e.timestamp || 0) < timeWindowMs);
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const categoryCounts = {};
    let totalScore = 0;
    let blockedCount = 0;
    let allowedCount = 0;

    recentEvents.forEach(e => {
        severityCounts[e.severity || 'info']++;
        categoryCounts[e.category || 'unknown'] = (categoryCounts[e.category || 'unknown'] || 0) + 1;
        totalScore += e.score || 0;
        if (e.blocked) blockedCount++;
        else allowedCount++;
    });

    const total = recentEvents.length;
    const avgScore = total > 0 ? totalScore / total : 0;

    return {
        summary: {
            totalEvents: total,
            blockedRequests: blockedCount,
            allowedRequests: allowedCount,
            blockRate: total > 0 ? round((blockedCount / total) * 100, 1) : 0,
            averageThreatScore: round(avgScore, 2),
            peakThreatScore: total > 0 ? Math.max(...recentEvents.map(e => e.score || 0)) : 0,
        },
        severity: severityCounts,
        categories: categoryCounts,
        topCategories: Object.entries(categoryCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([name, count]) => ({ name, count, percentage: round((count / total) * 100, 1) })),
        timeWindow: { ms: timeWindowMs, label: formatDuration(timeWindowMs) },
        calculatedAt: now,
    };
}

/**
 * Calculate model performance metrics.
 * @param {Array} requests - Array of model requests with timing data
 * @returns {Object} Performance metrics
 */
export function calculatePerformanceMetrics(requests) {
    if (!requests || requests.length === 0) {
        return { latency: {}, throughput: {}, tokenMetrics: {}, errorRate: 0 };
    }

    const latencies = requests.filter(r => r.responseTime).map(r => r.responseTime);
    const tokenCounts = requests.filter(r => r.tokens).map(r => r.tokens);
    const errorCount = requests.filter(r => r.error || r.statusCode >= 400).length;

    return {
        latency: {
            ...calculateStats(latencies),
            p50: latencies.length ? round(percentile(latencies, 50), 2) : 0,
            p90: latencies.length ? round(percentile(latencies, 90), 2) : 0,
            p95: latencies.length ? round(percentile(latencies, 95), 2) : 0,
            p99: latencies.length ? round(percentile(latencies, 99), 2) : 0,
        },
        throughput: {
            totalRequests: requests.length,
            requestsPerMinute: requests.length > 1
                ? round(requests.length / ((requests[requests.length - 1].timestamp - requests[0].timestamp) / 60000), 2)
                : 0,
        },
        tokenMetrics: {
            ...calculateStats(tokenCounts),
            totalTokens: tokenCounts.reduce((s, v) => s + v, 0),
        },
        errorRate: round((errorCount / requests.length) * 100, 2),
        errorCount,
        successCount: requests.length - errorCount,
    };
}

// ============================================================================
// Color Utilities for Charts
// ============================================================================

/**
 * Generate a color palette for charts.
 * @param {number} count - Number of colors needed
 * @param {string} scheme - Color scheme ('default', 'severity', 'warm', 'cool')
 * @returns {string[]} Array of CSS color strings
 */
export function generateChartColors(count, scheme = 'default') {
    const palettes = {
        default: ['#6366f1', '#8b5cf6', '#a78bfa', '#c084fc', '#818cf8', '#60a5fa', '#38bdf8', '#22d3ee', '#2dd4bf', '#34d399', '#4ade80', '#a3e635'],
        severity: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4'],
        warm: ['#ef4444', '#f97316', '#f59e0b', '#eab308', '#d97706', '#ea580c', '#dc2626', '#b91c1c'],
        cool: ['#6366f1', '#3b82f6', '#06b6d4', '#14b8a6', '#10b981', '#22d3ee', '#0ea5e9', '#8b5cf6'],
        neon: ['#00ff87', '#60efff', '#ff6f91', '#ffc75f', '#845ec2', '#d65db1', '#ff9671', '#ffc75f'],
    };

    const palette = palettes[scheme] || palettes.default;
    const colors = [];
    for (let i = 0; i < count; i++) {
        colors.push(palette[i % palette.length]);
    }
    return colors;
}

/**
 * Get severity color.
 * @param {string} severity - Severity level
 * @returns {Object} Color values
 */
export function getSeverityColor(severity) {
    const colors = {
        critical: { bg: '#fee2e2', text: '#991b1b', border: '#ef4444', accent: '#dc2626' },
        high: { bg: '#ffedd5', text: '#9a3412', border: '#f97316', accent: '#ea580c' },
        medium: { bg: '#fef9c3', text: '#854d0e', border: '#eab308', accent: '#ca8a04' },
        low: { bg: '#dcfce7', text: '#166534', border: '#22c55e', accent: '#16a34a' },
        info: { bg: '#dbeafe', text: '#1e40af', border: '#3b82f6', accent: '#2563eb' },
    };
    return colors[severity] || colors.info;
}

/**
 * Interpolate between two colors.
 * @param {string} color1 - Start color (hex)
 * @param {string} color2 - End color (hex)
 * @param {number} factor - Interpolation factor (0-1)
 * @returns {string} Interpolated color (hex)
 */
export function interpolateColor(color1, color2, factor) {
    const hex = (c) => parseInt(c, 16);
    const r1 = hex(color1.slice(1, 3)), g1 = hex(color1.slice(3, 5)), b1 = hex(color1.slice(5, 7));
    const r2 = hex(color2.slice(1, 3)), g2 = hex(color2.slice(3, 5)), b2 = hex(color2.slice(5, 7));
    const r = Math.round(r1 + (r2 - r1) * factor);
    const g = Math.round(g1 + (g2 - g1) * factor);
    const b = Math.round(b1 + (b2 - b1) * factor);
    return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
}

// ============================================================================
// Helpers
// ============================================================================

function round(value, decimals) {
    return Math.round(value * Math.pow(10, decimals)) / Math.pow(10, decimals);
}

// ============================================================================
// Exports
// ============================================================================

export default {
    formatDuration, formatNumber, formatBytes, formatPercentage, getRelativeTime,
    generateTimeBuckets, calculateStats, percentile, movingAverage, exponentialMovingAverage,
    detectOutliers, correlation, linearRegression,
    eventsToTimeSeries, groupByCategory, createHeatmapData,
    analyzeTrend, forecast,
    calculateSecurityMetrics, calculatePerformanceMetrics,
    generateChartColors, getSeverityColor, interpolateColor,
};
