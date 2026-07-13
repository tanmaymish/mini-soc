import React from 'react';
import clsx from 'clsx';
import { Search, Menu } from 'lucide-react';

// Top command bar: page title, global alert search, environment status, user.
export default function TopBar({ title, query, onQuery, searchId, demoMode, error, items, active, onSelect }) {
    return (
        <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/80 backdrop-blur">
            <div className="flex items-center gap-4 px-4 lg:px-6 h-16">
                <div className="min-w-0 flex items-center gap-2">
                    <span className="text-xs text-slate-600 hidden md:inline">Operations</span>
                    <span className="text-slate-700 hidden md:inline">/</span>
                    <h1 className="text-sm font-semibold text-slate-200 truncate">{title}</h1>
                </div>

                {/* Global search */}
                <div className="relative ml-auto w-40 sm:w-64 lg:w-80">
                    <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                    <input
                        id={searchId}
                        type="text"
                        value={query}
                        onChange={(e) => onQuery(e.target.value)}
                        placeholder="Search alerts…  ( / )"
                        className="w-full bg-slate-900/70 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-brand-500/60 focus:ring-1 focus:ring-brand-500/40"
                    />
                </div>

                {/* Environment pill */}
                <div className="hidden md:flex items-center gap-2 bg-slate-900 px-3 py-1.5 rounded-full border border-slate-700 shrink-0">
                    <span className="relative flex h-2 w-2">
                        {!demoMode && !error && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />}
                        <span className={clsx('relative inline-flex rounded-full h-2 w-2',
                            demoMode ? 'bg-amber-400' : error ? 'bg-red-500' : 'bg-emerald-500')} />
                    </span>
                    <span className="text-xs font-medium text-slate-300">
                        {demoMode ? 'Demo' : error ? 'Offline' : 'Live'}
                    </span>
                </div>

                {/* User */}
                <div className="flex items-center gap-2.5 shrink-0">
                    <div className="hidden sm:block text-right leading-tight">
                        <div className="text-xs font-semibold text-slate-200">Security Analyst</div>
                        <div className="text-[10px] text-slate-500">Tier-2 · SOC</div>
                    </div>
                    <div className="h-8 w-8 rounded-full bg-gradient-to-br from-brand-500 to-violet-500 flex items-center justify-center text-xs font-bold text-white">
                        AN
                    </div>
                </div>
            </div>

            {/* Mobile nav strip (sidebar is hidden below lg) */}
            <div className="lg:hidden flex items-center gap-1 px-3 pb-2 overflow-x-auto">
                <Menu className="h-4 w-4 text-slate-600 shrink-0 mr-1" />
                {items.map((it) => (
                    <button
                        key={it.key}
                        onClick={() => onSelect(it.key)}
                        className={clsx(
                            'shrink-0 flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors',
                            active === it.key ? 'bg-brand-500/15 text-brand-200 border border-brand-500/40'
                                : 'text-slate-400 border border-transparent hover:text-slate-200',
                        )}
                    >
                        {it.label}
                        {it.badge > 0 && <span className="text-[10px] font-bold">({it.badge})</span>}
                    </button>
                ))}
            </div>
        </header>
    );
}
