import React, { useMemo, useState } from 'react';
import clsx from 'clsx';
import { Cpu, ChevronDown } from 'lucide-react';
import { RULES } from '../simEngine';

const SEV_DOT = {
    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500',
};
const SEV_TEXT = {
    critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400',
};

export default function DetectionRules({ alerts }) {
    const [open, setOpen] = useState(true);

    const counts = useMemo(() => {
        const c = {};
        for (const a of alerts) c[a.rule_name] = (c[a.rule_name] || 0) + 1;
        return c;
    }, [alerts]);

    const totalFired = Object.values(counts).reduce((s, n) => s + n, 0);

    return (
        <div className="bg-slate-800/60 rounded-xl border border-slate-700 shadow-lg mb-8">
            <button
                onClick={() => setOpen((o) => !o)}
                className="w-full flex items-center justify-between px-5 py-4"
            >
                <div className="flex items-center gap-2">
                    <Cpu className="h-5 w-5 text-brand-500" />
                    <h2 className="text-lg font-bold text-slate-100">Detection Rule Engine</h2>
                    <span className="text-xs text-slate-500 hidden sm:inline">
                        {RULES.length} rules armed · Python · <code className="text-slate-400">app/detection/rules/</code>
                    </span>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-xs bg-brand-500/20 text-brand-300 px-2 py-1 rounded font-bold border border-brand-500/30">
                        {totalFired} MATCHES
                    </span>
                    <ChevronDown className={clsx('h-4 w-4 text-slate-400 transition-transform', open && 'rotate-180')} />
                </div>
            </button>

            {open && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 px-5 pb-5">
                    {RULES.map((r) => {
                        const n = counts[r.name] || 0;
                        return (
                            <div
                                key={r.name}
                                className={clsx(
                                    'rounded-lg border p-3 transition-colors',
                                    n > 0 ? 'border-slate-600 bg-slate-900/80' : 'border-slate-800 bg-slate-900/40'
                                )}
                            >
                                <div className="flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2 min-w-0">
                                        <span className={clsx('h-2 w-2 rounded-full shrink-0',
                                            n > 0 ? SEV_DOT[r.severity] : 'bg-slate-600', n > 0 && 'animate-pulse')} />
                                        <span className="font-mono text-sm text-slate-200 truncate">{r.name}</span>
                                    </div>
                                    <div className="flex items-center gap-2 shrink-0">
                                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
                                            {r.category}
                                        </span>
                                        <span className={clsx('text-xs font-bold tabular-nums', n > 0 ? SEV_TEXT[r.severity] : 'text-slate-600')}>
                                            ×{n}
                                        </span>
                                    </div>
                                </div>
                                <p className="text-xs text-slate-500 mt-1.5 leading-snug">{r.logic}</p>
                                <div className="mt-1.5">
                                    <span className="text-[10px] font-mono text-cyan-400/80">
                                        {r.mitre.technique} · {r.mitre.tactic}
                                    </span>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
