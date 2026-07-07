import React from 'react';
import {
    KeyRound, Radar, Database, Code, Globe, UserCog, Cpu, Zap, Trash2,
    ShieldAlert, Boxes, Fingerprint, Crosshair, Keyboard,
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

// Keyboard shortcut shown per attack: 1–9 then 0 for the tenth.
const shortcutFor = (i) => (i < 9 ? String(i + 1) : i === 9 ? '0' : null);

function Kbd({ children }) {
    return (
        <kbd className="font-mono text-[10px] font-bold text-slate-400 bg-slate-950/70 border border-slate-700 rounded px-1.5 py-0.5 leading-none">
            {children}
        </kbd>
    );
}

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
                        {!running && <Kbd>U</Kbd>}
                    </button>
                    <button
                        onClick={onReset}
                        title="Clear the board (R)"
                        className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm font-semibold px-3 py-2 rounded-lg transition-colors"
                    >
                        <Trash2 className="h-4 w-4" />
                        <Kbd>R</Kbd>
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
                {ATTACK_KEYS.map((key, i) => {
                    const a = ATTACKS[key];
                    const Icon = ICONS[a.icon] || Zap;
                    const kbd = shortcutFor(i);
                    return (
                        <button
                            key={key}
                            onClick={() => onAttack(key)}
                            className={`group relative flex flex-col items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/60 px-2 py-3 transition-all active:scale-95 ${COLOR[a.color]}`}
                        >
                            {kbd && (
                                <span className="absolute top-1 right-1.5 font-mono text-[9px] font-bold text-slate-600 group-hover:text-slate-400 transition-colors">
                                    {kbd}
                                </span>
                            )}
                            <Icon className="h-5 w-5 transition-transform group-hover:scale-110" />
                            <span className="text-[11px] font-semibold leading-tight text-center text-slate-300 group-hover:text-inherit">
                                {a.label}
                            </span>
                        </button>
                    );
                })}
            </div>

            <p className="mt-3 text-[11px] text-slate-500 flex items-center gap-1.5 flex-wrap">
                <Keyboard className="h-3.5 w-3.5" />
                Shortcuts: <Kbd>1</Kbd>–<Kbd>0</Kbd> launch an attack · <Kbd>U</Kbd> unleash all ·
                <Kbd>R</Kbd> reset board · <Kbd>/</Kbd> search alerts
            </p>
        </div>
    );
}
