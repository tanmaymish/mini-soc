import React from 'react';
import clsx from 'clsx';
import { Radar, FlaskConical } from 'lucide-react';

// Left navigation rail — the primary "this is a platform" chrome.
export default function Sidebar({ items, active, onSelect, demoMode, error }) {
    return (
        <aside className="hidden lg:flex w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-950/70 backdrop-blur sticky top-0 h-screen">
            {/* Brand */}
            <div className="flex items-center gap-2.5 px-5 h-16 border-b border-slate-800">
                <div className="bg-brand-500/20 border border-brand-500/30 rounded-lg p-1.5">
                    <Radar className="h-6 w-6 text-brand-500" />
                </div>
                <div className="leading-tight">
                    <div className="font-bold text-slate-100 tracking-tight">Mini SOC</div>
                    <div className="text-[10px] uppercase tracking-widest text-slate-500">Security Platform</div>
                </div>
            </div>

            {/* Nav */}
            <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-0.5">
                <p className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-widest text-slate-600">Operations</p>
                {items.map((it) => {
                    const Icon = it.icon;
                    const isActive = active === it.key;
                    return (
                        <button
                            key={it.key}
                            onClick={() => onSelect(it.key)}
                            className={clsx(
                                'group relative w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                                isActive
                                    ? 'bg-brand-500/10 text-brand-200'
                                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60',
                            )}
                        >
                            {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-brand-500" />}
                            <Icon className={clsx('h-4.5 w-4.5 shrink-0', isActive ? 'text-brand-400' : 'text-slate-500 group-hover:text-slate-300')} />
                            <span className="flex-1 text-left">{it.label}</span>
                            {it.badge > 0 && (
                                <span className={clsx(
                                    'text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center',
                                    it.badgeTone || 'bg-slate-700 text-slate-300',
                                )}>
                                    {it.badge > 99 ? '99+' : it.badge}
                                </span>
                            )}
                        </button>
                    );
                })}
            </nav>

            {/* Footer status */}
            <div className="border-t border-slate-800 px-4 py-3">
                <div className="flex items-center gap-2 text-xs">
                    {demoMode ? (
                        <>
                            <FlaskConical className="h-3.5 w-3.5 text-amber-400" />
                            <span className="text-amber-300 font-medium">Demo environment</span>
                        </>
                    ) : (
                        <>
                            <span className="relative flex h-2 w-2">
                                {!error && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />}
                                <span className={clsx('relative inline-flex rounded-full h-2 w-2', error ? 'bg-red-500' : 'bg-emerald-500')} />
                            </span>
                            <span className="text-slate-400 font-medium">{error ? 'Engine offline' : 'Engine online'}</span>
                        </>
                    )}
                </div>
                <div className="text-[10px] text-slate-600 mt-1.5">v1.0 · SOAR pipeline</div>
            </div>
        </aside>
    );
}
