import React from 'react';
import clsx from 'clsx';
import { ShieldAlert, AlertTriangle, Info, Shield } from 'lucide-react';

export default function StatCard({ title, value, type }) {
    const getIcon = () => {
        switch (type) {
            case 'critical': return <ShieldAlert className="h-6 w-6 text-red-500" />;
            case 'warning': return <AlertTriangle className="h-6 w-6 text-orange-500" />;
            case 'info': return <Info className="h-6 w-6 text-blue-500" />;
            default: return <Shield className="h-6 w-6 text-slate-400" />;
        }
    };

    return (
        <div className="bg-slate-800 rounded-lg p-6 flex items-center justify-between border border-slate-700 shadow-lg">
            <div>
                <h3 className="text-slate-400 text-sm font-medium tracking-wide pb-1">{title}</h3>
                <p className={clsx(
                    "text-3xl font-bold",
                    type === 'critical' && "text-red-400",
                    type === 'warning' && "text-orange-400",
                    type === 'info' && "text-blue-400",
                    !type && "text-slate-100"
                )}>
                    {value}
                </p>
            </div>
            <div className="bg-slate-900 p-3 rounded-full">
                {getIcon()}
            </div>
        </div>
    );
}
