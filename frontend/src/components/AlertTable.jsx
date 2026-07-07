import React, { useState } from 'react';
import { formatDistanceToNow, format } from 'date-fns';
import clsx from 'clsx';
import { ShieldCheck, Check, CheckCircle2, XCircle, ShieldBan, RotateCcw } from 'lucide-react';
import {
    STATUS_NEW, STATUS_ACK, STATUS_RESOLVED, STATUS_FALSE_POSITIVE,
    STATUS_META, normStatus, isOpen, alertKey,
} from '../alertStatus';

// A single analyst-action button used inside the expanded evidence row.
function ActionButton({ onClick, disabled, active, tone, icon, children }) {
    const Icon = icon;
    const tones = {
        amber: 'hover:border-amber-500/60 hover:bg-amber-500/10 text-amber-300',
        emerald: 'hover:border-emerald-500/60 hover:bg-emerald-500/10 text-emerald-300',
        slate: 'hover:border-slate-500/60 hover:bg-slate-500/10 text-slate-300',
        red: 'hover:border-red-500/60 hover:bg-red-500/10 text-red-300',
    };
    return (
        <button
            type="button"
            onClick={onClick}
            disabled={disabled}
            className={clsx(
                'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-semibold transition-colors',
                disabled
                    ? 'border-slate-800 text-slate-600 cursor-not-allowed'
                    : clsx('border-slate-700 bg-slate-900/60', tones[tone]),
                active && 'ring-1 ring-inset',
            )}
        >
            <Icon className="h-3.5 w-3.5" />
            {children}
        </button>
    );
}

export default function AlertTable({ alerts, onTriage, onBlock, blockedIps }) {
    const [expandedId, setExpandedId] = useState(null);
    const blocked = blockedIps || new Set();

    const toggleExpand = (id) => {
        setExpandedId(expandedId === id ? null : id);
    };

    const getSeverityColor = (severity) => {
        switch ((severity || '').toLowerCase()) {
            case 'critical': return 'bg-red-500/20 text-red-400 border border-red-500/30';
            case 'high': return 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
            case 'medium': return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
            default: return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
        }
    };

    if (!alerts || alerts.length === 0) {
        return (
            <div className="bg-slate-800 rounded-lg border border-slate-700 p-12 text-center shadow-lg">
                <p className="text-slate-400">No alerts match the current filter. Network is quiet.</p>
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
                        <th scope="col" className="px-6 py-4 font-semibold">Status</th>
                        <th scope="col" className="px-6 py-4 font-semibold text-right">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts.map((alert) => {
                        const id = alertKey(alert);
                        const status = normStatus(alert.status);
                        const meta = STATUS_META[status];
                        const closed = !isOpen(status);
                        const ipBlocked = blocked.has(alert.source_ip);
                        return (
                            <React.Fragment key={id}>
                                <tr
                                    className={clsx(
                                        'bg-slate-800 border-b border-slate-700 hover:bg-slate-700/50 transition-colors cursor-pointer',
                                        alert.isNew && 'row-new',
                                        closed && 'opacity-55',
                                    )}
                                    onClick={() => toggleExpand(id)}
                                >
                                    <td className="px-6 py-4 whitespace-nowrap opacity-80">
                                        {alert.timestamp ? formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true }) : 'Just now'}
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className={clsx('px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wide', getSeverityColor(alert.severity))}>
                                            {alert.severity}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 font-medium font-mono text-slate-200">
                                        {alert.rule_name}
                                        {alert.mitre && (
                                            <a
                                                href={`https://attack.mitre.org/techniques/${alert.mitre.technique}/`}
                                                target="_blank"
                                                rel="noreferrer"
                                                onClick={(e) => e.stopPropagation()}
                                                title={`${alert.mitre.name} · ${alert.mitre.tactic}`}
                                                className="ml-2 text-xs font-semibold text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 rounded px-1.5 py-0.5 align-middle"
                                            >
                                                {alert.mitre.technique}
                                            </a>
                                        )}
                                    </td>
                                    <td className="px-6 py-4 font-mono text-brand-400">
                                        <span className="inline-flex items-center gap-1.5">
                                            {alert.source_ip}
                                            {ipBlocked && (
                                                <ShieldBan className="h-3.5 w-3.5 text-emerald-400" title="Source IP blocked" />
                                            )}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4">
                                        <span className={clsx('px-2 py-0.5 rounded-full text-[11px] font-semibold whitespace-nowrap', meta.badge)}>
                                            {meta.label}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-right">
                                        <button className="text-brand-500 hover:text-brand-400 text-xs font-semibold tracking-wide uppercase transition-colors">
                                            {expandedId === id ? 'Hide Evidence' : 'View Evidence'}
                                        </button>
                                    </td>
                                </tr>

                                {/* Expandable Evidence + analyst actions */}
                                {expandedId === id && (
                                    <tr className="bg-slate-900/50 border-b border-slate-700">
                                        <td colSpan={6} className="px-6 py-6">
                                            <div className="flex flex-col gap-4">
                                                {/* Analyst triage / response bar */}
                                                {(onTriage || onBlock) && (
                                                    <div className="flex flex-wrap items-center gap-2 pb-1">
                                                        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider mr-1">Analyst actions</span>
                                                        {onTriage && (
                                                            <>
                                                                <ActionButton
                                                                    tone="amber" icon={Check}
                                                                    active={status === STATUS_ACK}
                                                                    disabled={status === STATUS_ACK}
                                                                    onClick={() => onTriage(alert, STATUS_ACK)}
                                                                >Acknowledge</ActionButton>
                                                                <ActionButton
                                                                    tone="emerald" icon={CheckCircle2}
                                                                    active={status === STATUS_RESOLVED}
                                                                    disabled={status === STATUS_RESOLVED}
                                                                    onClick={() => onTriage(alert, STATUS_RESOLVED)}
                                                                >Resolve</ActionButton>
                                                                <ActionButton
                                                                    tone="slate" icon={XCircle}
                                                                    active={status === STATUS_FALSE_POSITIVE}
                                                                    disabled={status === STATUS_FALSE_POSITIVE}
                                                                    onClick={() => onTriage(alert, STATUS_FALSE_POSITIVE)}
                                                                >False positive</ActionButton>
                                                                {closed && (
                                                                    <ActionButton
                                                                        tone="slate" icon={RotateCcw}
                                                                        onClick={() => onTriage(alert, STATUS_NEW)}
                                                                    >Reopen</ActionButton>
                                                                )}
                                                            </>
                                                        )}
                                                        {onBlock && (
                                                            <ActionButton
                                                                tone="red" icon={ShieldBan}
                                                                disabled={ipBlocked}
                                                                onClick={() => onBlock(alert)}
                                                            >{ipBlocked ? 'IP blocked' : `Block ${alert.source_ip}`}</ActionButton>
                                                        )}
                                                    </div>
                                                )}

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
                                                                        'font-bold',
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
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}
