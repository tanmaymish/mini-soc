import React, { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';
import clsx from 'clsx';

export default function LiveConsole({ lines }) {
    const endRef = useRef(null);

    useEffect(() => {
        endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }, [lines]);

    return (
        <div className="bg-slate-950 rounded-xl border border-slate-800 shadow-lg overflow-hidden mb-8">
            <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-800 bg-slate-900/80">
                <span className="flex gap-1.5">
                    <span className="h-3 w-3 rounded-full bg-red-500/80" />
                    <span className="h-3 w-3 rounded-full bg-yellow-500/80" />
                    <span className="h-3 w-3 rounded-full bg-green-500/80" />
                </span>
                <Terminal className="h-4 w-4 text-slate-500 ml-2" />
                <span className="text-xs font-mono text-slate-400">/var/log/soc — live ingestion</span>
                <span className="ml-auto flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-emerald-400">
                    <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" /> streaming
                </span>
            </div>
            <div className="h-56 overflow-y-auto px-4 py-3 font-mono text-xs leading-relaxed">
                {lines.length === 0 && (
                    <div className="text-slate-600">waiting for traffic…</div>
                )}
                {lines.map((l) => (
                    <div
                        key={l.id}
                        className={clsx(
                            'whitespace-pre-wrap break-all',
                            l.kind === 'attack' ? 'text-red-400' : 'text-slate-500'
                        )}
                    >
                        <span className="text-slate-600 mr-2">{l.time}</span>
                        {l.kind === 'attack' && <span className="text-red-500 mr-1">⚠</span>}
                        {l.raw}
                    </div>
                ))}
                <div ref={endRef} />
            </div>
        </div>
    );
}
