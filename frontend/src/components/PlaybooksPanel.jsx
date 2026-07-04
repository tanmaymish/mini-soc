import React, { useMemo } from 'react';
import { Workflow, ArrowRight, ShieldBan, UserX, Gauge, KeyRound, LogOut } from 'lucide-react';
import { PLAYBOOKS } from '../simEngine';

const ACTION_ICON = {
    BLOCK_IP: ShieldBan, DISABLE_USER: UserX, RATE_LIMIT: Gauge,
    REQUIRE_REAUTH: KeyRound, DISABLE_SESSION: LogOut,
};

export default function PlaybooksPanel({ mitigations }) {
    const execCounts = useMemo(() => {
        const c = {};
        for (const m of mitigations) c[m.action] = (c[m.action] || 0) + 1;
        return c;
    }, [mitigations]);

    return (
        <div className="bg-slate-800/60 rounded-xl border border-slate-700 p-5 shadow-lg">
            <div className="flex items-center gap-2 mb-1">
                <Workflow className="h-5 w-5 text-emerald-400" />
                <h2 className="text-lg font-bold text-slate-100">SOAR Playbooks</h2>
            </div>
            <p className="text-slate-400 text-sm mb-4">
                When a rule fires at high/critical severity, the matching playbook runs automatically —
                no analyst in the loop.
            </p>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {PLAYBOOKS.map((pb) => {
                    const Icon = ACTION_ICON[pb.action] || Workflow;
                    const n = execCounts[pb.action] || 0;
                    return (
                        <div key={pb.name} className="rounded-lg border border-slate-700 bg-slate-900/60 p-3">
                            <div className="flex items-center justify-between gap-2 mb-2">
                                <div className="flex items-center gap-2">
                                    <Icon className="h-4 w-4 text-emerald-400" />
                                    <span className="font-mono text-sm text-slate-200">{pb.action}</span>
                                </div>
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                    {n} EXECUTED
                                </span>
                            </div>

                            {/* trigger → action flow */}
                            <div className="flex items-center flex-wrap gap-1.5 text-[11px]">
                                <span className="flex flex-wrap gap-1">
                                    {pb.triggers.map((t) => (
                                        <span key={t} className="font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
                                            {t}
                                        </span>
                                    ))}
                                </span>
                                <ArrowRight className="h-3 w-3 text-slate-600" />
                                <span className="text-emerald-400 font-semibold">{pb.name}</span>
                            </div>

                            <p className="text-xs text-slate-500 mt-2">{pb.effect}.</p>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
