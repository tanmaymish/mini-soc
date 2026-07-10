import React from 'react';
import clsx from 'clsx';
import { Gamepad2, ShieldHalf, Zap, Flame, Trophy, RotateCcw, X, Crosshair } from 'lucide-react';
import { rankFor, CONTAINS_PER_WAVE } from '../defenseGame';

const SEV_DOT = {
    critical: 'bg-red-500', high: 'bg-orange-500',
    medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-blue-500',
};

function IntegrityBar({ value }) {
    const color = value > 60 ? 'bg-emerald-500' : value > 30 ? 'bg-amber-500' : 'bg-red-500';
    return (
        <div className="flex items-center gap-2 min-w-[160px]">
            <ShieldHalf className={clsx('h-4 w-4', value > 30 ? 'text-emerald-400' : 'text-red-400')} />
            <div className="flex-1">
                <div className="flex justify-between text-[10px] uppercase tracking-wider text-slate-400 mb-0.5">
                    <span>SOC Integrity</span><span className="font-mono">{Math.round(value)}%</span>
                </div>
                <div className="h-2 rounded-full bg-slate-700 overflow-hidden">
                    <div className={clsx('h-full transition-[width] duration-300', color)} style={{ width: `${value}%` }} />
                </div>
            </div>
        </div>
    );
}

function Stat({ icon, label, value, tone }) {
    const Icon = icon;
    return (
        <div className="flex items-center gap-2">
            <Icon className={clsx('h-4 w-4', tone)} />
            <div className="leading-tight">
                <div className="text-[10px] uppercase tracking-wider text-slate-400">{label}</div>
                <div className={clsx('font-bold font-mono text-sm', tone)}>{value}</div>
            </div>
        </div>
    );
}

function ThreatCard({ threat, now, onContain }) {
    const remaining = Math.max(0, threat.at - now);
    const total = threat.at - threat.start || 1;
    const pct = Math.max(0, Math.min(100, (remaining / total) * 100));
    const secs = Math.ceil(remaining / 1000);
    const bar = pct > 50 ? 'bg-emerald-500' : pct > 25 ? 'bg-amber-500' : 'bg-red-500';
    const urgent = pct <= 25;
    return (
        <div className={clsx(
            'shrink-0 w-52 rounded-lg border bg-slate-900/70 p-2.5',
            urgent ? 'border-red-500/60' : 'border-slate-700',
            urgent && 'defense-urgent',
        )}>
            <div className="flex items-center gap-2 mb-1">
                <span className={clsx('h-2 w-2 rounded-full shrink-0', SEV_DOT[threat.sev] || 'bg-blue-500')} />
                <span className="font-mono text-xs text-slate-200 truncate">{threat.rule}</span>
                <span className={clsx('ml-auto font-mono text-xs font-bold', urgent ? 'text-red-400' : 'text-slate-400')}>{secs}s</span>
            </div>
            <div className="text-[11px] font-mono text-slate-500 mb-1.5 truncate">{threat.ip}</div>
            <div className="h-1.5 rounded-full bg-slate-700 overflow-hidden mb-2">
                <div className={clsx('h-full transition-[width] duration-200', bar)} style={{ width: `${pct}%` }} />
            </div>
            <button
                type="button"
                onClick={() => onContain(threat.key)}
                className="w-full flex items-center justify-center gap-1.5 rounded-md bg-red-500/90 hover:bg-red-500 text-white text-xs font-bold py-1.5 transition-colors"
            >
                <Crosshair className="h-3.5 w-3.5" /> Contain
            </button>
        </div>
    );
}

export default function DefenseHUD({ defense, threats, now, onContain, onEnd, onRestart, onClose }) {
    // Game-over / shift-complete summary modal.
    if (defense.over) {
        const breached = defense.integrity <= 0;
        const rank = rankFor(defense.score);
        return (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
                <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl overflow-hidden defense-modal-in">
                    <div className={clsx('px-6 py-5 border-b border-slate-800',
                        breached ? 'bg-red-500/10' : 'bg-emerald-500/10')}>
                        <h2 className={clsx('text-2xl font-black tracking-tight flex items-center gap-2',
                            breached ? 'text-red-400' : 'text-emerald-400')}>
                            {breached ? <Flame className="h-6 w-6" /> : <Trophy className="h-6 w-6" />}
                            {breached ? 'SOC BREACHED' : 'SHIFT COMPLETE'}
                        </h2>
                        <p className="text-slate-400 text-sm mt-1">
                            {breached
                                ? 'The perimeter fell. Every unhandled threat chipped away your integrity.'
                                : 'You stood down the attack stream. Nice work, analyst.'}
                        </p>
                    </div>

                    <div className="p-6">
                        <div className="flex items-center gap-4 mb-5">
                            <div className={clsx('flex h-16 w-16 items-center justify-center rounded-xl border-2 text-3xl font-black', rank.ring, rank.color)}>
                                {rank.grade}
                            </div>
                            <div>
                                <div className="text-[11px] uppercase tracking-wider text-slate-500">Analyst rank</div>
                                <div className={clsx('text-lg font-bold', rank.color)}>{rank.label}</div>
                            </div>
                            <div className="ml-auto text-right">
                                <div className="text-[11px] uppercase tracking-wider text-slate-500">Score</div>
                                <div className="text-2xl font-black font-mono text-slate-100">{defense.score.toLocaleString()}</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-3 gap-2 mb-6 text-center">
                            {[['Wave', defense.wave], ['Contained', defense.contained], ['Breached', defense.breached]].map(([l, v]) => (
                                <div key={l} className="rounded-lg bg-slate-800/70 border border-slate-700 py-2">
                                    <div className="text-lg font-bold font-mono text-slate-100">{v}</div>
                                    <div className="text-[10px] uppercase tracking-wider text-slate-500">{l}</div>
                                </div>
                            ))}
                        </div>

                        <div className="flex gap-2">
                            <button onClick={onRestart}
                                className="flex-1 flex items-center justify-center gap-2 bg-brand-500 hover:bg-brand-500/90 text-white font-bold text-sm py-2.5 rounded-lg transition-colors">
                                <RotateCcw className="h-4 w-4" /> Play again
                            </button>
                            <button onClick={onClose}
                                className="px-4 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold text-sm py-2.5 rounded-lg transition-colors">
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    if (!defense.active) return null;

    const queue = Object.values(threats).sort((a, b) => a.at - b.at);
    const toNextWave = CONTAINS_PER_WAVE - (defense.contained % CONTAINS_PER_WAVE);

    return (
        <div className="sticky top-3 z-40 mb-6 rounded-xl border border-brand-500/40 bg-slate-900/95 backdrop-blur shadow-2xl shadow-brand-500/10">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-brand-300 font-bold">
                    <Gamepad2 className="h-5 w-5" /> SOC Defense
                </div>
                <IntegrityBar value={defense.integrity} />
                <Stat icon={Trophy} label="Score" value={defense.score.toLocaleString()} tone="text-slate-100" />
                <Stat icon={Zap} label="Combo" value={`×${defense.combo}`} tone="text-amber-300" />
                <Stat icon={Flame} label="Wave" value={defense.wave} tone="text-red-300" />
                <Stat icon={ShieldHalf} label="Active" value={queue.length} tone="text-brand-300" />
                <div className="ml-auto flex items-center gap-3">
                    <span className="hidden sm:block text-[11px] text-slate-500">{toNextWave} to next wave</span>
                    <button onClick={onEnd}
                        className="flex items-center gap-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors">
                        <X className="h-3.5 w-3.5" /> End shift
                    </button>
                </div>
            </div>

            <div className="px-4 py-3">
                {queue.length === 0 ? (
                    <p className="text-sm text-slate-500 py-2 text-center">Perimeter clear — hold the line, next wave incoming…</p>
                ) : (
                    <div className="flex gap-2 overflow-x-auto pb-1">
                        {queue.map((t) => (
                            <ThreatCard key={t.key} threat={t} now={now} onContain={onContain} />
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
