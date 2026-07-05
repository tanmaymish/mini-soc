import React, { useMemo } from 'react';
import clsx from 'clsx';
import { Clock, AlertTriangle, Zap } from 'lucide-react';

const SEV = {
    critical: 'bg-red-500 text-red-400', high: 'bg-orange-500 text-orange-400',
    medium: 'bg-yellow-500 text-yellow-400', low: 'bg-blue-500 text-blue-400',
    soar: 'bg-emerald-500 text-emerald-400',
};

const hhmmss = (t) => {
    const d = new Date(t);
    return isNaN(d) ? '--:--:--' : d.toLocaleTimeString('en-GB');
};

export default function IncidentTimeline({ alerts, mitigations }) {
    const events = useMemo(() => {
        const evs = [];
        for (const a of alerts) {
            evs.push({
                t: a.timestamp || a.created_at, kind: 'alert', sev: a.severity,
                label: a.rule_name,
                text: `${a.rule_name} — ${a.severity.toUpperCase()} from ${a.source_ip || 'local'}`,
            });
        }
        for (const m of mitigations) {
            evs.push({
                t: m.timestamp, kind: 'soar', sev: 'soar',
                label: m.action,
                text: `SOAR: ${m.action} → ${m.target} (${m.playbook})`,
            });
        }
        return evs
            .filter((e) => e.t)
            .sort((a, b) => new Date(b.t) - new Date(a.t))
            .slice(0, 14);
    }, [alerts, mitigations]);

    return (
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-5 shadow-lg">
            <div className="flex items-center gap-2 mb-4">
                <Clock className="h-5 w-5 text-brand-500" />
                <h2 className="text-lg font-bold text-slate-100">Incident Timeline</h2>
            </div>

            {events.length === 0 ? (
                <div className="h-40 flex items-center justify-center text-slate-500 text-sm">
                    No events yet — launch an attack to build the timeline.
                </div>
            ) : (
                <div className="relative pl-5 max-h-[420px] overflow-y-auto">
                    {/* spine */}
                    <div className="absolute left-[7px] top-1 bottom-1 w-px bg-slate-700" />
                    {events.map((e, i) => (
                        <div key={i} className="relative mb-3 last:mb-0">
                            <span className={clsx('absolute -left-[13px] top-1 h-2.5 w-2.5 rounded-full ring-4 ring-slate-800',
                                SEV[e.sev]?.split(' ')[0] || 'bg-slate-500')} />
                            <div className="flex items-baseline gap-2">
                                <span className="font-mono text-[11px] text-slate-500 shrink-0">{hhmmss(e.t)}</span>
                                {e.kind === 'soar'
                                    ? <Zap className="h-3 w-3 text-emerald-400 shrink-0" />
                                    : <AlertTriangle className={clsx('h-3 w-3 shrink-0', SEV[e.sev]?.split(' ')[1])} />}
                                <span className="text-xs text-slate-300 leading-snug">{e.text}</span>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
