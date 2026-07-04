import React, { useMemo } from 'react';
import {
    ResponsiveContainer, PieChart, Pie, Cell,
    BarChart, Bar, XAxis, YAxis, Tooltip, AreaChart, Area, CartesianGrid,
} from 'recharts';

const SEV_COLORS = { critical: '#ef4444', high: '#f59e0b', medium: '#eab308', low: '#3b82f6' };

const Card = ({ title, children }) => (
    <div className="bg-slate-800 rounded-xl border border-slate-700 p-4 shadow-lg">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">{title}</h3>
        {children}
    </div>
);

const tooltipStyle = {
    contentStyle: { background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 12 },
    labelStyle: { color: '#94a3b8' },
    itemStyle: { color: '#e2e8f0' },
};

export default function ThreatCharts({ alerts, timeline }) {
    const sevData = useMemo(() => {
        const c = {};
        alerts.forEach((a) => { c[a.severity] = (c[a.severity] || 0) + 1; });
        return ['critical', 'high', 'medium', 'low']
            .filter((s) => c[s])
            .map((s) => ({ name: s, value: c[s] }));
    }, [alerts]);

    const tacticData = useMemo(() => {
        const c = {};
        alerts.forEach((a) => {
            const t = a.mitre?.tactic;
            if (t) c[t] = (c[t] || 0) + 1;
        });
        return Object.entries(c)
            .map(([tactic, count]) => ({ tactic, count }))
            .sort((a, b) => b.count - a.count);
    }, [alerts]);

    const total = alerts.length;

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
            <Card title="Threats over time">
                <ResponsiveContainer width="100%" height={180}>
                    <AreaChart data={timeline} margin={{ top: 5, right: 8, left: -20, bottom: 0 }}>
                        <defs>
                            <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.7} />
                                <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                        <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 10 }} interval="preserveEnd" />
                        <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 10 }} />
                        <Tooltip {...tooltipStyle} />
                        <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} fill="url(#g)" isAnimationActive={false} />
                    </AreaChart>
                </ResponsiveContainer>
            </Card>

            <Card title="Severity mix">
                <div className="relative">
                    <ResponsiveContainer width="100%" height={180}>
                        <PieChart>
                            <Pie
                                data={sevData.length ? sevData : [{ name: 'none', value: 1 }]}
                                dataKey="value" nameKey="name"
                                cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={2}
                                isAnimationActive={false}
                            >
                                {(sevData.length ? sevData : [{ name: 'none' }]).map((d, i) => (
                                    <Cell key={i} fill={SEV_COLORS[d.name] || '#334155'} stroke="#0f172a" />
                                ))}
                            </Pie>
                            <Tooltip {...tooltipStyle} />
                        </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                        <span className="text-2xl font-extrabold text-slate-100">{total}</span>
                        <span className="text-[10px] uppercase tracking-wider text-slate-500">alerts</span>
                    </div>
                </div>
            </Card>

            <Card title="MITRE ATT&CK tactics">
                {tacticData.length === 0 ? (
                    <div className="h-[180px] flex items-center justify-center text-slate-500 text-sm">
                        No detections yet
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height={180}>
                        <BarChart data={tacticData} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
                            <XAxis type="number" allowDecimals={false} tick={{ fill: '#64748b', fontSize: 10 }} />
                            <YAxis type="category" dataKey="tactic" width={120} tick={{ fill: '#94a3b8', fontSize: 10 }} />
                            <Tooltip {...tooltipStyle} cursor={{ fill: '#1e293b' }} />
                            <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} isAnimationActive={false} />
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </Card>
        </div>
    );
}
