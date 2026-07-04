import React from 'react';
import {
    KeyRound, Radar, Database, Code, Globe, UserCog, Cpu, Zap, Trash2,
    ShieldAlert, Boxes, Fingerprint, Crosshair,
} from 'lucide-react';
import { ATTACKS, ATTACK_KEYS } from '../simEngine';

const ICONS = {
    KeyRound, Radar, Database, Code, Globe, UserCog, Cpu,
    ShieldAlert, Boxes, Fingerprint, Crosshair,
};

const COLOR = {
    red: 'hover:border-red-500/60 hover:bg-red-500/10 text-red-300',
    orange: 'hover:border-orange-500/60 hover:bg-orange-500/10 text-orange-300',
    yellow: 'hover:border-yellow-500/60 hover:bg-yellow-500/10 text-yellow-300',
};

export default function AttackSimulator({ onAttack, onUnleash, onReset, running }) {
    return (
        <div className="bg-slate-800/60 rounded-xl border border-slate-700 p-5 mb-8 shadow-lg">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
                <div>
                    <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                        <Zap className="h-5 w-5 text-brand-500" />
                        Attack Simulator
                    </h2>
                    <p className="text-slate-400 text-sm">
                        Launch a live attack and watch the SOC detect, tag (MITRE ATT&amp;CK) and auto-contain it.
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={onUnleash}
                        disabled={running}
                        className="flex items-center gap-2 bg-red-500/90 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-bold px-4 py-2 rounded-lg transition-colors shadow"
                    >
                        <Zap className="h-4 w-4" />
                        {running ? 'Under attack…' : 'Unleash all'}
                    </button>
                    <button
                        onClick={onReset}
                        title="Clear the board"
                        className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm font-semibold px-3 py-2 rounded-lg transition-colors"
                    >
                        <Trash2 className="h-4 w-4" />
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
                {ATTACK_KEYS.map((key) => {
                    const a = ATTACKS[key];
                    const Icon = ICONS[a.icon] || Zap;
                    return (
                        <button
                            key={key}
                            onClick={() => onAttack(key)}
                            className={`group flex flex-col items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/60 px-2 py-3 transition-all active:scale-95 ${COLOR[a.color]}`}
                        >
                            <Icon className="h-5 w-5 transition-transform group-hover:scale-110" />
                            <span className="text-[11px] font-semibold leading-tight text-center text-slate-300 group-hover:text-inherit">
                                {a.label}
                            </span>
                        </button>
                    );
                })}
            </div>
        </div>
    );
}
