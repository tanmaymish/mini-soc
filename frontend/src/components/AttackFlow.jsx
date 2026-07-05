import React from 'react';
import clsx from 'clsx';
import { Crosshair, ChevronRight, ShieldCheck, Radar, KeyRound, Swords, UserCog, EyeOff, RadioTower } from 'lucide-react';

// Icon + accent per kill-chain phase.
const PHASE = {
    'Reconnaissance': { icon: Radar, color: 'text-cyan-400 border-cyan-500/40 bg-cyan-500/10' },
    'Credential Access': { icon: KeyRound, color: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10' },
    'Initial Access': { icon: Swords, color: 'text-orange-400 border-orange-500/40 bg-orange-500/10' },
    'Privilege Escalation': { icon: UserCog, color: 'text-red-400 border-red-500/40 bg-red-500/10' },
    'Defense Evasion': { icon: EyeOff, color: 'text-purple-400 border-purple-500/40 bg-purple-500/10' },
    'Command & Control': { icon: RadioTower, color: 'text-pink-400 border-pink-500/40 bg-pink-500/10' },
    'Execution': { icon: Swords, color: 'text-orange-400 border-orange-500/40 bg-orange-500/10' },
};

const Node = ({ children, className, icon: Icon, sub }) => (
    <div className={clsx('flex flex-col items-center gap-1 rounded-lg border px-3 py-2 min-w-[104px] text-center', className)}>
        {Icon && <Icon className="h-4 w-4" />}
        <span className="text-[11px] font-semibold leading-tight">{children}</span>
        {sub && <span className="text-[9px] font-mono opacity-70 leading-none">{sub}</span>}
    </div>
);

const Arrow = () => (
    <ChevronRight className="h-5 w-5 text-slate-600 shrink-0 attack-flow-arrow" />
);

export default function AttackFlow({ incident }) {
    if (!incident) {
        return (
            <div className="bg-slate-800/60 rounded-xl border border-slate-700 p-6 text-center text-sm text-slate-400 shadow-lg">
                Launch an <span className="text-slate-200 font-semibold">APT Campaign</span> to visualize the attack path.
            </div>
        );
    }

    return (
        <div className="bg-slate-800/60 rounded-xl border border-slate-700 p-5 shadow-lg">
            <div className="flex items-center gap-2 mb-4">
                <Crosshair className="h-5 w-5 text-red-400" />
                <h2 className="text-lg font-bold text-slate-100">Attack Flow</h2>
                <span className="font-mono text-[11px] text-slate-500">{incident.incident_id}</span>
            </div>

            <div className="flex items-center gap-2 overflow-x-auto pb-2">
                {/* Attacker */}
                <Node className="text-red-400 border-red-500/40 bg-red-500/10" icon={Crosshair} sub={incident.actor}>
                    Attacker
                </Node>

                {/* Kill-chain phases */}
                {incident.stages.map((phase) => {
                    const p = PHASE[phase] || PHASE['Execution'];
                    return (
                        <React.Fragment key={phase}>
                            <Arrow />
                            <Node className={p.color} icon={p.icon}>{phase}</Node>
                        </React.Fragment>
                    );
                })}

                {/* Auto-containment terminal node */}
                <Arrow />
                <Node className="text-emerald-400 border-emerald-500/40 bg-emerald-500/10" icon={ShieldCheck} sub="SOAR">
                    Contained
                </Node>
            </div>

            <p className="text-xs text-slate-400 mt-3 leading-relaxed">{incident.narrative}</p>
        </div>
    );
}
