import React from 'react';

// Consistent page-level heading used at the top of every console view.
export default function SectionHeader({ icon: Icon, title, subtitle, accent = 'text-brand-400', children }) {
    return (
        <div className="flex items-end justify-between gap-4 mb-6 flex-wrap">
            <div className="flex items-center gap-3">
                {Icon && (
                    <div className="bg-slate-800/80 border border-slate-700 rounded-lg p-2">
                        <Icon className={`h-5 w-5 ${accent}`} />
                    </div>
                )}
                <div>
                    <h1 className="text-xl font-bold tracking-tight text-slate-100">{title}</h1>
                    {subtitle && <p className="text-sm text-slate-400">{subtitle}</p>}
                </div>
            </div>
            {children && <div className="flex items-center gap-2">{children}</div>}
        </div>
    );
}
