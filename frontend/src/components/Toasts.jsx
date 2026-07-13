import React from 'react';
import clsx from 'clsx';
import { CheckCircle2, ShieldBan, Info, Zap, X } from 'lucide-react';

const ICON = {
    success: CheckCircle2,
    block: ShieldBan,
    attack: Zap,
    info: Info,
};

const TONE = {
    success: 'border-emerald-500/40 text-emerald-300',
    block: 'border-red-500/40 text-red-300',
    attack: 'border-amber-500/40 text-amber-300',
    info: 'border-brand-500/40 text-brand-300',
};

/**
 * Bottom-right toast stack. Toasts are owned by the Dashboard and auto-expire;
 * this component just renders them and offers a manual dismiss.
 */
export default function Toasts({ toasts, onDismiss }) {
    if (!toasts || toasts.length === 0) return null;
    return (
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-[min(92vw,22rem)] pointer-events-none">
            {toasts.map((t) => {
                const Icon = ICON[t.tone] || Info;
                return (
                    <div
                        key={t.id}
                        role="status"
                        className={clsx(
                            'pointer-events-auto flex items-start gap-2.5 rounded-lg border bg-slate-900/95 backdrop-blur px-3.5 py-2.5 shadow-xl toast-in',
                            TONE[t.tone] || TONE.info,
                        )}
                    >
                        <Icon className="h-4 w-4 mt-0.5 shrink-0" />
                        <p className="text-sm text-slate-200 flex-1 leading-snug">{t.text}</p>
                        <button
                            type="button"
                            onClick={() => onDismiss(t.id)}
                            className="text-slate-500 hover:text-slate-300 shrink-0"
                            aria-label="Dismiss"
                        >
                            <X className="h-3.5 w-3.5" />
                        </button>
                    </div>
                );
            })}
        </div>
    );
}
