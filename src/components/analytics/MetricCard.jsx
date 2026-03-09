import React from 'react';
import { Activity, Clock, ShieldAlert, Cpu } from 'lucide-react';

const icons = {
    activity: Activity,
    clock: Clock,
    shield: ShieldAlert,
    cpu: Cpu
};

const MetricCard = ({ title, value, icon, color }) => {
    const IconComponent = icons[icon] || Activity;

    return (
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-md flex items-center justify-between">
            <div>
                <p className="text-gray-400 text-sm mb-1">{title}</p>
                <p className="text-3xl font-bold font-mono tracking-tight text-white">{value}</p>
            </div>
            <div className={`p-4 bg-gray-900 rounded-lg ${color}`}>
                <IconComponent className="w-8 h-8" />
            </div>
        </div>
    );
};

export default MetricCard;
