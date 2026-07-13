/**
 * Analyst triage model — shared by the alert toolbar and the alert table.
 *
 * An alert moves through a small workflow the analyst drives by hand:
 *   new → acknowledged → resolved   (or, at any point → false_positive)
 * "resolved" and "false_positive" are terminal (closed) states.
 */

export const STATUS_NEW = 'new';
export const STATUS_ACK = 'acknowledged';
export const STATUS_RESOLVED = 'resolved';
export const STATUS_FALSE_POSITIVE = 'false_positive';

// Order matters — this is the order chips render in the toolbar.
export const STATUSES = [STATUS_NEW, STATUS_ACK, STATUS_RESOLVED, STATUS_FALSE_POSITIVE];

export const STATUS_META = {
    [STATUS_NEW]: {
        label: 'New',
        badge: 'bg-brand-500/15 text-brand-300 border border-brand-500/30',
        chip: 'text-brand-300 border-brand-500/40',
    },
    [STATUS_ACK]: {
        label: 'Acknowledged',
        badge: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
        chip: 'text-amber-300 border-amber-500/40',
    },
    [STATUS_RESOLVED]: {
        label: 'Resolved',
        badge: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
        chip: 'text-emerald-300 border-emerald-500/40',
    },
    [STATUS_FALSE_POSITIVE]: {
        label: 'False positive',
        badge: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
        chip: 'text-slate-300 border-slate-500/40',
    },
};

// Closed states no longer count as "open" work for the analyst.
export const CLOSED_STATUSES = new Set([STATUS_RESOLVED, STATUS_FALSE_POSITIVE]);

export const isOpen = (status) => !CLOSED_STATUSES.has(status || STATUS_NEW);

// Normalise whatever a backend / demo alert carries into a known status.
export const normStatus = (status) =>
    STATUSES.includes(status) ? status : STATUS_NEW;

// Stable key for an alert across demo + live shapes.
export const alertKey = (a) => a._id || a.id || a.timestamp;
