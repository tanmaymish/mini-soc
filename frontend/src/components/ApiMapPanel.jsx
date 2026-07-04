import React, { useState, useMemo } from 'react';
import clsx from 'clsx';
import { Network, CornerDownRight } from 'lucide-react';
import { API_ROUTES, mapEndpoint } from '../simEngine';

const RISK = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/40',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/40',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/40',
    low: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/40',
    variable: 'text-purple-400 bg-purple-500/10 border-purple-500/40',
};
const IMPACT = {
    high: 'Admin / infra takeover', variable: 'Depends on query shape',
    medium: 'Account / data exposure', low: 'Limited', critical: 'Financial / data loss',
};

const RiskBadge = ({ risk }) => (
    <span className={clsx('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border', RISK[risk])}>
        {risk}
    </span>
);

export default function ApiMapPanel() {
    const [path, setPath] = useState('/api/admin/users');
    const mapped = useMemo(() => mapEndpoint(path), [path]);

    return (
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-5 shadow-lg">
            <div className="flex items-center gap-2 mb-1">
                <Network className="h-5 w-5 text-brand-500" />
                <h2 className="text-lg font-bold text-slate-100">API → Service → Risk Mapping</h2>
            </div>
            <p className="text-slate-400 text-sm mb-4">
                Every request is resolved to a security domain and a base risk before detection runs.
            </p>

            {/* Interactive probe */}
            <div className="mb-4">
                <label className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Probe an endpoint</label>
                <input
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    spellCheck={false}
                    className="w-full mt-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 font-mono text-sm text-emerald-400 focus:outline-none focus:border-brand-500"
                    placeholder="/api/admin/users"
                />
                {/* Strict output block */}
                <div className="mt-3 bg-slate-950 rounded-lg border border-slate-800 p-3 font-mono text-xs space-y-1">
                    <Row k="API Endpoint" v={path || '—'} />
                    <Row k="Mapped Service" v={mapped.service} />
                    <Row k="Risk Level" v={<RiskBadge risk={mapped.risk} />} />
                    <Row k="Business Impact" v={IMPACT[mapped.risk]} />
                    <Row k="Rules Watching" v={
                        mapped.watched.length
                            ? <span className="flex flex-wrap gap-1">{mapped.watched.map((w) => (
                                <span key={w} className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-400">{w}</span>
                            ))}</span>
                            : '—'
                    } />
                </div>
            </div>

            {/* Full routing table */}
            <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                    <thead className="text-slate-500 uppercase tracking-wider border-b border-slate-700">
                        <tr>
                            <th className="py-2 pr-3 font-semibold">Endpoint</th>
                            <th className="py-2 pr-3 font-semibold">Service</th>
                            <th className="py-2 font-semibold">Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {API_ROUTES.map((r) => (
                            <tr key={r.pattern} className={clsx('border-b border-slate-800/70',
                                r.service === mapped.service && 'bg-brand-500/5')}>
                                <td className="py-2 pr-3 font-mono text-slate-300">
                                    {r.service === mapped.service && <CornerDownRight className="h-3 w-3 text-brand-500 inline mr-1" />}
                                    {r.pattern}
                                </td>
                                <td className="py-2 pr-3 text-slate-400">{r.service}</td>
                                <td className="py-2"><RiskBadge risk={r.risk} /></td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

const Row = ({ k, v }) => (
    <div className="flex gap-2">
        <span className="text-slate-500 w-28 shrink-0">{k}:</span>
        <span className="text-slate-200 break-all">{v}</span>
    </div>
);
