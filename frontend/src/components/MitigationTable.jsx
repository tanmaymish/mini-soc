import React, { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import clsx from 'clsx';
import { ShieldBan, UserX } from 'lucide-react';

export default function MitigationTable({ mitigations }) {
    const [expandedId, setExpandedId] = useState(null);

    const toggleExpand = (id) => {
        setExpandedId(expandedId === id ? null : id);
    };

    const getActionIcon = (action) => {
        switch (action) {
            case 'BLOCK_IP': return <ShieldBan className="h-4 w-4 text-emerald-400" />;
            case 'DISABLE_USER': return <UserX className="h-4 w-4 text-blue-400" />;
            default: return null;
        }
    };

    if (!mitigations || mitigations.length === 0) {
        return (
            <div className="bg-slate-800 rounded-lg border border-slate-700 p-8 text-center shadow-lg">
                <p className="text-slate-400">No active AI mitigations. SOAR Engine is standing by.</p>
            </div>
        );
    }

    return (
        <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden shadow-lg mt-8">
            <table className="w-full text-left text-sm text-slate-300 relative">
                <thead className="text-xs uppercase bg-slate-900 border-b border-slate-700 text-slate-400 tracking-wider">
                    <tr>
                        <th scope="col" className="px-6 py-4 font-semibold">Time</th>
                        <th scope="col" className="px-6 py-4 font-semibold">Action</th>
                        <th scope="col" className="px-6 py-4 font-semibold">Target</th>
                        <th scope="col" className="px-6 py-4 font-semibold">Playbook Ext.</th>
                        <th scope="col" className="px-6 py-4 font-semibold text-right">Details</th>
                    </tr>
                </thead>
                <tbody>
                    {mitigations.map((m) => (
                        <React.Fragment key={m._id || m.timestamp}>
                            <tr
                                className="bg-slate-800 border-b border-slate-700 hover:bg-slate-700/50 transition-colors cursor-pointer"
                                onClick={() => toggleExpand(m._id || m.timestamp)}
                            >
                                <td className="px-6 py-4 whitespace-nowrap opacity-80">
                                    {m.timestamp ? formatDistanceToNow(new Date(m.timestamp), { addSuffix: true }) : 'Just now'}
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-2">
                                        {getActionIcon(m.action)}
                                        <span className="font-bold uppercase tracking-wide text-xs text-slate-200">
                                            {m.action}
                                        </span>
                                    </div>
                                </td>
                                <td className="px-6 py-4 font-medium font-mono text-brand-400">
                                    {m.target}
                                </td>
                                <td className="px-6 py-4 font-mono text-slate-400 text-xs">
                                    {m.playbook}
                                </td>
                                <td className="px-6 py-4 text-right">
                                    <button className="text-emerald-500 hover:text-emerald-400 text-xs font-semibold tracking-wide uppercase transition-colors">
                                        {expandedId === (m._id || m.timestamp) ? 'Hide' : 'View'}
                                    </button>
                                </td>
                            </tr>

                            {/* Expandable Reason Row */}
                            {expandedId === (m._id || m.timestamp) && (
                                <tr className="bg-slate-900/50 border-b border-slate-700">
                                    <td colSpan={5} className="px-6 py-6">
                                        <div className="flex flex-col gap-2">
                                            <div>
                                                <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Containment Reason</h4>
                                                <p className="text-slate-300 bg-slate-950 p-3 rounded border border-slate-800">{m.reason}</p>
                                            </div>
                                            <div className="flex items-center gap-2 mt-2">
                                                <span className="text-xs text-slate-500 uppercase tracking-wider font-bold bg-emerald-500/10 px-2 py-1 rounded inline-block border border-emerald-500/20 text-emerald-400">
                                                    Status: {m.status || 'Active'}
                                                </span>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            )}
                        </React.Fragment>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
