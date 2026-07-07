import React from 'react';
import clsx from 'clsx';
import { Search, X, SlidersHorizontal } from 'lucide-react';
import { STATUSES, STATUS_META } from '../alertStatus';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const SEV_CHIP = {
    critical: 'text-red-300 border-red-500/40',
    high: 'text-orange-300 border-orange-500/40',
    medium: 'text-yellow-300 border-yellow-500/40',
    low: 'text-blue-300 border-blue-500/40',
};

function Chip({ active, onClick, className, children }) {
    return (
        <button
            type="button"
            onClick={onClick}
            className={clsx(
                'px-2.5 py-1 rounded-full text-xs font-semibold border transition-colors',
                active
                    ? clsx('bg-slate-700/70', className)
                    : 'bg-slate-900/50 border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600',
            )}
        >
            {children}
        </button>
    );
}

/**
 * Filter/search bar that sits above the alert feed. Purely presentational —
 * all state lives in the Dashboard so triage counts stay in sync.
 */
export default function AlertToolbar({ filter, onChange, shown, total, searchId }) {
    const dirty = filter.sev !== 'all' || filter.status !== 'all' || filter.q.trim() !== '';

    return (
        <div className="bg-slate-800/60 rounded-lg border border-slate-700 p-3 mb-4 shadow-sm">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
                {/* Search */}
                <div className="relative flex-1 min-w-[180px]">
                    <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <input
                        id={searchId}
                        type="text"
                        value={filter.q}
                        onChange={(e) => onChange({ q: e.target.value })}
                        placeholder="Search IP, rule, MITRE, description…  ( / )"
                        className="w-full bg-slate-900/70 border border-slate-700 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-brand-500/60 focus:ring-1 focus:ring-brand-500/40"
                    />
                    {filter.q && (
                        <button
                            type="button"
                            onClick={() => onChange({ q: '' })}
                            className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                            aria-label="Clear search"
                        >
                            <X className="h-4 w-4" />
                        </button>
                    )}
                </div>

                {/* Severity filter */}
                <div className="flex items-center gap-1.5">
                    <SlidersHorizontal className="h-3.5 w-3.5 text-slate-500 mr-1" />
                    <Chip active={filter.sev === 'all'} onClick={() => onChange({ sev: 'all' })}
                        className="border-slate-500/50 text-slate-100">All</Chip>
                    {SEVERITIES.map((s) => (
                        <Chip key={s} active={filter.sev === s} onClick={() => onChange({ sev: s })}
                            className={SEV_CHIP[s]}>
                            {s[0].toUpperCase() + s.slice(1)}
                        </Chip>
                    ))}
                </div>

                {/* Status filter */}
                <div className="flex items-center gap-1.5">
                    <Chip active={filter.status === 'all'} onClick={() => onChange({ status: 'all' })}
                        className="border-slate-500/50 text-slate-100">Any status</Chip>
                    {STATUSES.map((s) => (
                        <Chip key={s} active={filter.status === s} onClick={() => onChange({ status: s })}
                            className={STATUS_META[s].chip}>
                            {STATUS_META[s].label}
                        </Chip>
                    ))}
                </div>

                {/* Count + clear */}
                <div className="flex items-center gap-3 ml-auto">
                    <span className="text-xs text-slate-400 font-mono whitespace-nowrap">
                        {shown === total
                            ? `${total} alert${total === 1 ? '' : 's'}`
                            : `${shown} / ${total} shown`}
                    </span>
                    {dirty && (
                        <button
                            type="button"
                            onClick={() => onChange({ sev: 'all', status: 'all', q: '' })}
                            className="text-xs font-semibold text-slate-300 hover:text-white bg-slate-700/70 hover:bg-slate-600 px-2.5 py-1 rounded-full transition-colors flex items-center gap-1"
                        >
                            <X className="h-3 w-3" /> Clear
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
