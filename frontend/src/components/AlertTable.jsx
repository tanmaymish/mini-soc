import React, { useState } from 'react';
import { formatDistanceToNow, format } from 'date-fns';
import clsx from 'clsx';
import { ShieldCheck } from 'lucide-react';

export default function AlertTable({ alerts }) {
    const [expandedId, setExpandedId] = useState(null);

    const toggleExpand = (id) => {
        setExpandedId(expandedId === id ? null : id);
    };

    const getSeverityColor = (severity) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'bg-red-500/20 text-red-400 border border-red-500/30';
            case 'high': return 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
            case 'medium': return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
            default: return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
        }
    };

    if (!alerts || alerts.length === 0) {
        return (
            <div className="bg-slate-800 rounded-lg border border-slate-700 p-12 text-center shadow-lg">
                <p className="text-slate-400">No active threats detected. Network is secure.</p>
            </div>
        );
    }

    return (
        <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden shadow-lg">
            <table className="w-full text-left text-sm text-slate-300 relative">
                <thead className="text-xs uppercase bg-slate-900 border-b border-slate-700 text-slate-400 tracking-wider">
                    <tr>
                        <th scope="col" className="px-6 py-4 font-semibold">Time</th>
                        <th scope="col" className="px-6 py-4 font-semibold">Severity</th>
                        <th scope="col" className="px-6 py-4 font-semibold">Rule Triggered</th>
                        <th scope="col" className="px-6 py-4 font-semibold">Source IP</th>
                        <th scope="col" className="px-6 py-4 font-semibold text-right">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts.map((alert) => (
                        <React.Fragment key={alert._id || alert.timestamp}>
                            <tr
                                className="bg-slate-800 border-b border-slate-700 hover:bg-slate-700/50 transition-colors cursor-pointer"
                                onClick={() => toggleExpand(alert._id || alert.timestamp)}
                            >
                                <td className="px-6 py-4 whitespace-nowrap opacity-80">
                                    {alert.timestamp ? formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true }) : 'Just now'}
                                </td>
                                <td className="px-6 py-4">
                                    <span className={clsx("px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wide", getSeverityColor(alert.severity))}>
                                        {alert.severity}
                                    </span>
                                </td>
                                <td className="px-6 py-4 font-medium font-mono text-slate-200">
                                    {alert.rule_name}
                                </td>
                                <td className="px-6 py-4 font-mono text-brand-400">
                                    {alert.source_ip}
                                </td>
                                <td className="px-6 py-4 text-right">
                                    <button className="text-brand-500 hover:text-brand-400 text-xs font-semibold tracking-wide uppercase transition-colors">
                                        {expandedId === (alert._id || alert.timestamp) ? 'Hide Evidence' : 'View Evidence'}
                                    </button>
                                </td>
                            </tr>

                            {/* Expandable Evidence Row */}
                            {expandedId === (alert._id || alert.timestamp) && (
                                <tr className="bg-slate-900/50 border-b border-slate-700">
                                    <td colSpan={5} className="px-6 py-6">
                                        <div className="flex flex-col gap-4">
                                            {alert.context && (
                                                <div className="mb-2">
                                                    <h4 className="text-xs font-bold text-brand-400 flex items-center gap-2 uppercase tracking-wider mb-1">
                                                        <ShieldCheck className="h-4 w-4" /> Threat Intel Match
                                                    </h4>
                                                    <div className="bg-brand-900/30 text-brand-300 p-3 rounded border border-brand-500/30 font-mono text-sm shadow-inner">
                                                        {alert.context}
                                                    </div>
                                                </div>
                                            )}

                                            <div>
                                                <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Alert Description</h4>
                                                <p className="text-slate-300">{alert.description}</p>
                                            </div>

                                            {alert.metadata && Object.keys(alert.metadata).length > 0 && (
                                                <div>
                                                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Model Metadata</h4>
                                                    <pre className="bg-slate-950 p-3 rounded border border-slate-800 overflow-x-auto text-xs text-brand-300 mt-2 font-mono shadow-inner">
                                                        {JSON.stringify(alert.metadata, null, 2)}
                                                    </pre>
                                                </div>
                                            )}

                                            {alert.evidence && alert.evidence.length > 0 && (
                                                <div>
                                                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Raw Evidence ({alert.evidence.length} events)</h4>
                                                    <div className="max-h-64 overflow-y-auto rounded border border-slate-800 bg-slate-950 shadow-inner mt-2">
                                                        {alert.evidence.map((ev, idx) => (
                                                            <div key={idx} className="p-3 text-xs font-mono text-emerald-400 border-b border-slate-800/50 last:border-0 hover:bg-slate-900 transition-colors">
                                                                <span className="text-slate-500 mr-2">{format(new Date(ev.timestamp), 'HH:mm:ss')}</span>
                                                                <span className="text-slate-400 mr-2">[{ev.source_ip}:{ev.source_port} → {ev.destination_ip}:{ev.destination_port}]</span>
                                                                <span className={clsx(
                                                                    ev.action?.includes('FAIL') ? 'text-red-400' : 'text-emerald-400',
                                                                    "font-bold"
                                                                )}>
                                                                    {ev.action}
                                                                </span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            )}
                        </React.Fragment>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
