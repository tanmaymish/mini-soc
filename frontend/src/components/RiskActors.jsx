import React, { useMemo } from 'react';
import clsx from 'clsx';
import { Gauge } from 'lucide-react';

const WEIGHT = { critical: 40, high: 25, medium: 12, low: 5, info: 1 };

export default function RiskActors({ alerts }) {
    const actors = useMemo(() => {
        const by = {};
        for (const a of alerts) {
            const ip = a.source_ip;
            if (!ip) continue;
            (by[ip] ||= { ip, score: 0, rules: new Set() });
            by[ip].score += WEIGHT[a.severity] || 5;
            by[ip].rules.add(a.rule_name);
        }
        return Object.values(by)
            .map((x) => ({ ...x, rules: x.rules.size, score: Math.min(100, x.score) }))
            .sort((a, b) => b.score - a.score)
            .slice(0, 6);
    }, [alerts]);

    const band = (s) => (s >= 70 ? 'critical' : s >= 40 ? 'high' : s >= 20 ? 'medium' : 'low');
    const BAR = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-emerald-500' };
    const TXT = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-emerald-400' };

    return (
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-5 shadow-lg">
            <div className="flex items-center gap-2 mb-1">
                <Gauge className="h-5 w-5 text-brand-500" />
                <h2 className="text-lg font-bold text-slate-100">Risk Score by Actor</h2>
            </div>
            <p className="text-slate-400 text-sm mb-4">Per-IP risk, weighted by severity of correlated detections.</p>

            {actors.length === 0 ? (
                <div className="h-40 flex items-center justify-center text-slate-500 text-sm">
                    No actors scored yet — launch an attack.
                </div>
            ) : (
                <div className="space-y-3">
                    {actors.map((a) => {
                        const b = band(a.score);
                        return (
                            <div key={a.ip}>
                                <div className="flex items-center justify-between text-xs mb-1">
                                    <span className="font-mono text-slate-300">{a.ip}</span>
                                    <span className="text-slate-500">
                                        {a.rules} rule{a.rules !== 1 ? 's' : ''} ·
                                        <span className={clsx('font-bold ml-1', TXT[b])}>{a.score}/100</span>
                                    </span>
                                </div>
                                <div className="h-2 rounded-full bg-slate-900 overflow-hidden">
                                    <div className={clsx('h-full rounded-full transition-all', BAR[b])}
                                        style={{ width: `${a.score}%` }} />
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
