import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

const generateTimeSeriesData = (stats) => {
    const points = 12;
    const data = [];
    const base = Math.max(stats.totalAttempts, 10);
    for (let i = 0; i < points; i++) {
        const t = i / (points - 1);
        const blocked = Math.round(base * (0.3 + 0.6 * t) * (0.8 + Math.random() * 0.4));
        const flagged = Math.round(blocked * (0.1 + Math.random() * 0.15));
        const allowed = Math.round(blocked * (0.03 + Math.random() * 0.07));
        data.push({ time: `${String(i * 2).padStart(2, '0')}:00`, blocked, flagged, allowed });
    }
    return data;
};
const generateHeatmapData = () => {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const data = [];
    days.forEach((day, di) => {
        for (let h = 0; h < 24; h++) {
            const isWorkHours = h >= 8 && h <= 18;
            const isWeekday = di < 5;
            const base = isWorkHours && isWeekday ? 0.6 : isWorkHours ? 0.3 : 0.1;
            data.push({ day, hour: h, value: Math.min(1, base + Math.random() * 0.4) });
        }
    });
    return data;
};