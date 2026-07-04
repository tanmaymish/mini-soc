import React from 'react';
import clsx from 'clsx';
import { GitBranch, ChevronRight, ShieldAlert } from 'lucide-react';

const SEV = {
    critical: 'text-red-400 border-red-500/40 bg-red-500/10',
    high: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
    medium: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
    low: 'text-blue-400 border-blue-500/40 bg-blue-500/10',
};

export default function IncidentsPanel({ incidents }) {
    if (!incidents || incidents.length === 0) {
        return (
            <div className="bg-slate-800/60 rounded-xl border border-slate-700 p-8 text-center shadow-lg">
                <p className="text-slate-400 text-sm">
                    No correlated incidents. Launch an <span className="text-slate-200 font-semibold">APT Campaign</span> (or
                    several attacks from one source) to see the correlation engine stitch them into a kill-chain.
                </p>
            </div>
        );
    }

    return (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {incidents.map((inc) => (
                <div
                    key={inc.incident_id}
                    className={clsx('rounded-xl border p-4 shadow-lg',
                        SEV[inc.severity] || SEV.low)}
                >
                    <div className="flex items-start justify-between gap-3 mb-2">
                        <div className="flex items-center gap-2">
                            <ShieldAlert className="h-5 w-5" />
                            <div>
                                <div className="font-bold text-slate-100">{inc.title}</div>
                                <div className="font-mono text-[11px] text-slate-500">{inc.incident_id}</div>
                            </div>
                        </div>
                        <span className={clsx('px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border', SEV[inc.severity])}>
                            {inc.severity}
                        </span>
                    </div>

                    {/* Kill chain */}
                    <div className="flex items-center flex-wrap gap-1.5 my-3">
                        <GitBranch className="h-3.5 w-3.5 text-slate-500" />
                        {inc.stages.map((phase, i) => (
                            <React.Fragment key={phase}>
                                {i > 0 && <ChevronRight className="h-3 w-3 text-slate-600" />}
                                <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-slate-900/70 border border-slate-700 text-slate-300">
                                    {phase}
                                </span>
                            </React.Fragment>
                        ))}
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{inc.narrative}</p>

                    <div className="mt-3 flex items-center gap-2 flex-wrap">
                        {inc.rule_names.map((r) => (
                            <span key={r} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-400">
                                {r}
                            </span>
                        ))}
                    </div>
                </div>
            ))}
        </div>
    );
}
