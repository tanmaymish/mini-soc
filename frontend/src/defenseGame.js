/**
 * SOC Defense — game rules for the "defend the SOC" mode.
 *
 * Attacks stream in, each with a breach countdown. The analyst contains a
 * threat (block its IP or close the alert) before the timer runs out to
 * score; misses damage the SOC's integrity. Survive escalating waves.
 *
 * Pure helpers only — all state lives in the Dashboard.
 */

// Integrity lost when a threat of each severity breaches the perimeter.
export const DEFENSE_DAMAGE = { critical: 24, high: 16, medium: 10, low: 8, info: 8 };

// Base points for containing a threat, multiplied by the current combo.
const SCORE_BASE = { critical: 150, high: 110, medium: 80, low: 60, info: 60 };

// Contain this many threats to advance a wave.
export const CONTAINS_PER_WAVE = 5;

export const scoreFor = (sev, combo) => Math.round((SCORE_BASE[sev] || 60) * combo);

// Breach window (ms) shrinks as waves escalate — floor of 5s.
export const breachWindow = (wave) => Math.max(5000, 13000 - (wave - 1) * 900);

// Delay (ms) before the next threat spawns — gets faster each wave.
export const spawnDelay = (wave) =>
    Math.max(1300, 4200 - (wave - 1) * 340) + Math.random() * 1100;

export const initialDefense = () => ({
    active: false,
    integrity: 100,
    score: 0,
    combo: 0,
    wave: 1,
    contained: 0,
    breached: 0,
    over: false,
});

export function rankFor(score) {
    if (score >= 6000) return { grade: 'S', label: 'Elite Threat Hunter', color: 'text-amber-300', ring: 'border-amber-400/60' };
    if (score >= 3500) return { grade: 'A', label: 'Senior SOC Analyst', color: 'text-emerald-300', ring: 'border-emerald-400/60' };
    if (score >= 2000) return { grade: 'B', label: 'SOC Analyst', color: 'text-brand-300', ring: 'border-brand-400/60' };
    if (score >= 800) return { grade: 'C', label: 'Junior Analyst', color: 'text-slate-200', ring: 'border-slate-400/60' };
    return { grade: 'D', label: 'Trainee', color: 'text-slate-400', ring: 'border-slate-600' };
}
