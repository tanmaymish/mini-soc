import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import axios from 'axios';
import { Activity, ShieldCheck, Radar, Cpu, FlaskConical, GitBranch } from 'lucide-react';
import StatCard from './StatCard';
import AlertTable from './AlertTable';
import AlertToolbar from './AlertToolbar';
import MitigationTable from './MitigationTable';
import AttackSimulator from './AttackSimulator';
import ThreatCharts from './ThreatCharts';
import LiveConsole from './LiveConsole';
import LiveAttackMap from './LiveAttackMap';
import IncidentsPanel from './IncidentsPanel';
import DetectionRules from './DetectionRules';
import ApiMapPanel from './ApiMapPanel';
import RiskActors from './RiskActors';
import PlaybooksPanel from './PlaybooksPanel';
import Toasts from './Toasts';
import { getDemoAlerts, getDemoMitigations } from '../demoData';
import { ATTACK_KEYS, buildAttack, benignLog, correlateAlerts, randomAttackKey } from '../simEngine';
import {
    STATUS_NEW, STATUS_ACK, STATUS_META, CLOSED_STATUSES,
    normStatus, isOpen, alertKey,
} from '../alertStatus';

// Demo mode: interactive, self-contained build (e.g. GitHub Pages).
const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true';

const API_BASE = import.meta.env.VITE_API_BASE_URL ||
    (window.location.hostname === 'localhost' ? 'http://localhost:5000/api' : '/api');

const TIMELINE_BUCKETS = 24;
const SEARCH_INPUT_ID = 'alert-search';
const clock = () => new Date().toLocaleTimeString('en-GB');
let _lid = 0;
let _tid = 0;

function makeTimeline() {
    return Array.from({ length: TIMELINE_BUCKETS }, (_, i) => ({ t: '', count: 0, _k: i }));
}

// Compact duration for analyst KPIs: 42s, 3.5m, 1.2h.
function fmtDur(ms) {
    if (ms == null) return '—';
    const s = ms / 1000;
    if (s < 90) return `${Math.round(s)}s`;
    const m = s / 60;
    if (m < 90) return `${m < 10 ? m.toFixed(1) : Math.round(m)}m`;
    return `${(m / 60).toFixed(1)}h`;
}

export default function Dashboard() {
    const [alerts, setAlerts] = useState([]);
    const [mitigations, setMitigations] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [logs, setLogs] = useState([]);
    const [timeline, setTimeline] = useState(makeTimeline);
    const [running, setRunning] = useState(false);
    const [eventsAnalyzed, setEventsAnalyzed] = useState(10245);
    const [liveIncidents, setLiveIncidents] = useState([]);

    // Analyst interactivity: triage decisions, manual containment, feedback.
    // triage: alertKey → { status, openedAt, ackAt?, closedAt? } — the
    // timestamps drive the MTTA / MTTR analyst-performance metrics.
    const [triage, setTriage] = useState({});
    const [manualMitigations, setManualMitigations] = useState([]);
    const [filter, setFilter] = useState({ sev: 'all', status: 'all', q: '' });
    const [toasts, setToasts] = useState([]);
    const [liveFire, setLiveFire] = useState(false);

    const bucketHits = useRef(0);

    const dismissToast = useCallback((id) => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
    }, []);

    const addToast = useCallback((text, tone = 'info') => {
        const id = `t${_tid++}`;
        setToasts((prev) => [...prev.slice(-3), { id, text, tone }]);
        setTimeout(() => dismissToast(id), 4200);
    }, [dismissToast]);

    const pushLogs = useCallback((entries) => {
        const stamped = entries.map((e) => ({ ...e, id: `l${_lid++}`, time: clock() }));
        setLogs((prev) => [...prev, ...stamped].slice(-120));
        setEventsAnalyzed((n) => n + entries.length);
    }, []);

    // Alerts as displayed: analyst triage decisions overlay whatever the
    // source (sim or backend) reported.
    const shownAlerts = useMemo(
        () => alerts.map((a) => {
            const t = triage[alertKey(a)];
            return t ? { ...a, status: t.status } : a;
        }),
        [alerts, triage]);

    // Manual containment merges into the SOAR feed (manual first — newest).
    const allMitigations = useMemo(
        () => [...manualMitigations, ...mitigations],
        [manualMitigations, mitigations]);

    const blockedIps = useMemo(() => {
        const s = new Set();
        for (const m of allMitigations) {
            if (m.action === 'BLOCK_IP' && m.target) s.add(m.target);
        }
        return s;
    }, [allMitigations]);

    // Alert-feed filter (severity / status / free text).
    const filteredAlerts = useMemo(() => {
        const q = filter.q.trim().toLowerCase();
        return shownAlerts.filter((a) => {
            if (filter.sev !== 'all' && (a.severity || '').toLowerCase() !== filter.sev) return false;
            if (filter.status !== 'all' && normStatus(a.status) !== filter.status) return false;
            if (q) {
                const hay = [
                    a.source_ip, a.rule_name, a.description,
                    a.mitre?.technique, a.mitre?.name, a.mitre?.tactic,
                ].filter(Boolean).join(' ').toLowerCase();
                if (!hay.includes(q)) return false;
            }
            return true;
        });
    }, [shownAlerts, filter]);

    // Demo: incidents are correlated client-side from the alerts on the board.
    // Live: they come from the backend's correlation engine.
    const demoIncidents = useMemo(
        () => (DEMO_MODE ? correlateAlerts(alerts) : []), [alerts]);
    const incidents = DEMO_MODE ? demoIncidents : liveIncidents;

    // --- Analyst actions ----------------------------------------------------

    const handleTriage = useCallback((alert, status) => {
        const now = Date.now();
        setTriage((prev) => {
            const key = alertKey(alert);
            const cur = prev[key] || {};
            const entry = {
                ...cur,
                status,
                openedAt: cur.openedAt ?? new Date(alert.timestamp || now).getTime(),
            };
            if (status === STATUS_ACK && !entry.ackAt) entry.ackAt = now;
            if (CLOSED_STATUSES.has(status)) entry.closedAt = now;
            if (status === STATUS_NEW) { delete entry.ackAt; delete entry.closedAt; }
            return { ...prev, [key]: entry };
        });
        const meta = STATUS_META[status];
        addToast(
            `${alert.rule_name} from ${alert.source_ip} → ${meta.label}`,
            status === 'resolved' ? 'success' : 'info');
    }, [addToast]);

    // Analyst performance: mean time to acknowledge / resolve, cases closed.
    const perf = useMemo(() => {
        const entries = Object.values(triage);
        const mean = (arr, at) => arr.reduce((s, e) => s + Math.max(0, e[at] - e.openedAt), 0) / arr.length;
        const acked = entries.filter((e) => e.ackAt);
        const closed = entries.filter((e) => e.closedAt && CLOSED_STATUSES.has(e.status));
        return {
            closed: closed.length,
            mtta: acked.length ? mean(acked, 'ackAt') : null,
            mttr: closed.length ? mean(closed, 'closedAt') : null,
        };
    }, [triage]);

    const handleBlock = useCallback((alert) => {
        const ip = alert.source_ip;
        if (!ip || blockedIps.has(ip)) return;
        setManualMitigations((prev) => [{
            _id: `manual-${Date.now()}-${prev.length}`,
            timestamp: new Date().toISOString(),
            playbook: 'manual_containment',
            action: 'BLOCK_IP',
            target: ip,
            reason: `Manually blocked by analyst from alert '${alert.rule_name}'.`,
            status: 'applied',
            isNew: true,
        }, ...prev].slice(0, 50));
        pushLogs([{ raw: `soar: analyst issued BLOCK_IP for ${ip} (manual containment)`, kind: 'attack' }]);
        addToast(`Firewall rule pushed — ${ip} blocked`, 'block');
    }, [blockedIps, pushLogs, addToast]);

    const updateFilter = useCallback((patch) => {
        setFilter((prev) => ({ ...prev, ...patch }));
    }, []);

    // --- Demo mode: interactive simulation ---------------------------------

    const launchAttack = useCallback((key) => {
        const { alerts: a, mitigations: m, logs: l } = buildAttack(key);
        setAlerts((prev) => [...a, ...prev].slice(0, 50));
        if (m?.length) setMitigations((prev) => [...m, ...prev].slice(0, 50));
        pushLogs(l);
        bucketHits.current += a.length;
    }, [pushLogs]);

    const unleashAll = useCallback(() => {
        if (running) return;
        setRunning(true);
        ATTACK_KEYS.forEach((key, i) => {
            setTimeout(() => {
                launchAttack(key);
                if (i === ATTACK_KEYS.length - 1) setTimeout(() => setRunning(false), 600);
            }, i * 550);
        });
    }, [launchAttack, running]);

    const resetBoard = useCallback(() => {
        setAlerts([]);
        setMitigations([]);
        setManualMitigations([]);
        setTriage({});
        setLogs([]);
        setTimeline(makeTimeline());
        setFilter({ sev: 'all', status: 'all', q: '' });
        setLiveFire(false);
        bucketHits.current = 0;
    }, []);

    const toggleLiveFire = useCallback(() => {
        setLiveFire((on) => {
            addToast(on ? 'Live Fire disengaged — attack stream stopped'
                        : 'Live Fire engaged — incoming attack stream', 'attack');
            return !on;
        });
    }, [addToast]);

    // Live Fire: randomized attacks arrive on their own, like a real feed.
    useEffect(() => {
        if (!DEMO_MODE || !liveFire) return;
        let t;
        const schedule = () => {
            t = setTimeout(() => {
                launchAttack(randomAttackKey());
                schedule();
            }, 3000 + Math.random() * 5000);
        };
        schedule();
        return () => clearTimeout(t);
    }, [liveFire, launchAttack]);

    // Keyboard shortcuts: 1–0 launch attacks, U unleash, R reset, / search.
    useEffect(() => {
        const onKey = (e) => {
            if (e.metaKey || e.ctrlKey || e.altKey) return;
            const tag = e.target?.tagName;
            const typing = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;

            if (e.key === '/' && !typing) {
                e.preventDefault();
                document.getElementById(SEARCH_INPUT_ID)?.focus();
                return;
            }
            if (e.key === 'Escape' && tag === 'INPUT') {
                e.target.blur();
                return;
            }
            if (!DEMO_MODE || typing) return;

            if (/^[0-9]$/.test(e.key)) {
                const idx = e.key === '0' ? 9 : Number(e.key) - 1;
                if (ATTACK_KEYS[idx]) launchAttack(ATTACK_KEYS[idx]);
            } else if (e.key === 'u' || e.key === 'U') {
                unleashAll();
            } else if (e.key === 'r' || e.key === 'R') {
                resetBoard();
            } else if (e.key === 'l' || e.key === 'L') {
                toggleLiveFire();
            }
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [launchAttack, unleashAll, resetBoard, toggleLiveFire]);

    // Seed demo data + run ambient traffic and the rolling timeline.
    useEffect(() => {
        if (!DEMO_MODE) return;
        setAlerts(getDemoAlerts());
        setMitigations(getDemoMitigations());
        setLoading(false);

        const traffic = setInterval(() => {
            pushLogs([benignLog()]);
        }, 1400);

        const roll = setInterval(() => {
            setTimeline((prev) => {
                const next = [...prev.slice(1), { t: clock().slice(0, 5), count: bucketHits.current, _k: Date.now() }];
                bucketHits.current = 0;
                return next;
            });
        }, 2000);

        return () => { clearInterval(traffic); clearInterval(roll); };
    }, [pushLogs]);

    // --- Live mode: poll the real backend ----------------------------------

    useEffect(() => {
        if (DEMO_MODE) return;
        const fetchData = async () => {
            try {
                const [alertRes, mitigRes, statsRes, incRes] = await Promise.all([
                    axios.get(`${API_BASE}/alerts`),
                    axios.get(`${API_BASE}/mitigations`),
                    axios.get(`${API_BASE}/ingestion/stats`),
                    axios.get(`${API_BASE}/incidents`),
                ]);
                const sorted = [...alertRes.data.alerts].sort(
                    (a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                setAlerts(sorted);
                setMitigations(mitigRes.data);
                setEventsAnalyzed(statsRes.data.total_events ?? 0);
                setLiveIncidents(incRes.data || []);
                setError(null);
            } catch (err) {
                console.error('Error fetching SOC data:', err);
                setError('Failed to connect to SOAR API.');
            } finally {
                setLoading(false);
            }
        };
        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    const openAlerts = shownAlerts.filter((a) => isOpen(normStatus(a.status)));
    const criticalCount = openAlerts.filter((a) => a.severity === 'critical' || a.severity === 'high').length;

    return (
        <div className="p-6 md:p-8 max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
                <div className="flex items-center gap-3">
                    <div className="bg-brand-500/20 p-2 rounded-lg border border-brand-500/30">
                        <Radar className="h-8 w-8 text-brand-500" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Mini SOC Console</h1>
                        <p className="text-slate-400 text-sm">AI-Powered Threat Detection &amp; SOAR Defense</p>
                    </div>
                </div>

                <div className="flex items-center gap-2 bg-slate-800 px-4 py-2 rounded-full border border-slate-700 shadow-sm">
                    {DEMO_MODE ? (
                        <>
                            <FlaskConical className="h-3.5 w-3.5 text-amber-400" />
                            <span className="text-sm font-medium text-amber-300">Interactive Demo</span>
                        </>
                    ) : (
                        <>
                            <span className="relative flex h-3 w-3">
                                {error ? (
                                    <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500" />
                                ) : (
                                    <>
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                                        <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
                                    </>
                                )}
                            </span>
                            <span className="text-sm font-medium text-slate-300">
                                {error ? 'SOAR Engine Offline' : 'SOAR Active (Polling)'}
                            </span>
                        </>
                    )}
                </div>
            </div>

            {error && !DEMO_MODE && (
                <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-4 rounded-lg mb-8 shadow-sm flex items-center gap-3">
                    <Activity className="h-5 w-5" />
                    {error} Ensure Flask is running on port 5000.
                </div>
            )}

            {/* Interactive attack simulator (demo only) */}
            {DEMO_MODE && (
                <AttackSimulator
                    onAttack={launchAttack}
                    onUnleash={unleashAll}
                    onReset={resetBoard}
                    running={running}
                    liveFire={liveFire}
                    onToggleLiveFire={toggleLiveFire}
                />
            )}

            {/* Stats Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <StatCard title="Total Events Analyzed" value={eventsAnalyzed.toLocaleString()} type="info" />
                <StatCard title="Open Alerts" value={openAlerts.length} type="warning" />
                <StatCard title="Critical / High Threats" value={criticalCount} type={criticalCount > 0 ? 'critical' : ''} />
                <StatCard
                    title={perf.closed > 0 ? `Analyst MTTR · ${perf.closed} closed` : 'Analyst MTTR'}
                    value={fmtDur(perf.mttr)}
                    sub={perf.mtta != null ? `MTTA ${fmtDur(perf.mtta)}` : null}
                />
            </div>

            {/* Live global attack map — geolocated arcs to the SOC */}
            <LiveAttackMap alerts={alerts} />

            {/* Detection rule engine — the actual rules + live match counts */}
            <DetectionRules alerts={alerts} />

            {/* Charts */}
            <ThreatCharts alerts={alerts} timeline={timeline} />

            {/* API mapping (endpoint→service→risk) + per-actor risk scoring */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-8">
                <ApiMapPanel />
                <RiskActors alerts={alerts} />
            </div>

            {/* Correlated Incidents — multi-stage attacks stitched into a kill-chain */}
            <div className="mb-8">
                <div className="mb-4 flex items-center justify-between">
                    <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                        <GitBranch className="h-5 w-5 text-brand-500" />
                        Correlated Incidents
                    </h2>
                    {incidents.length > 0 && (
                        <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded font-bold border border-red-500/30">
                            {incidents.length} ACTIVE INCIDENT(S)
                        </span>
                    )}
                </div>
                <IncidentsPanel incidents={incidents} />
            </div>

            {/* SOAR playbooks — trigger → automated action, with live exec counts */}
            <div className="mb-8">
                <PlaybooksPanel mitigations={allMitigations} />
            </div>

            {/* Live log console (demo only) */}
            {DEMO_MODE && <LiveConsole lines={logs} />}

            {/* SOAR Mitigations Feed */}
            <div className="mb-12">
                <div className="mb-4 flex items-center justify-between">
                    <h2 className="text-lg font-bold text-emerald-400 flex items-center gap-2">
                        <Cpu className="h-5 w-5 text-emerald-400" />
                        Active SOAR Mitigations
                    </h2>
                    {allMitigations.length > 0 && (
                        <span className="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-1 rounded font-bold border border-emerald-500/30">
                            {allMitigations.length} ACTION(S) APPLIED
                        </span>
                    )}
                </div>
                <MitigationTable mitigations={allMitigations} />
            </div>

            {/* Threat Alert Feed — searchable, filterable, triageable */}
            <div>
                <div className="mb-4 flex items-center justify-between">
                    <h2 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5 text-slate-400" />
                        Threat Alert Feed
                    </h2>
                    {loading && <span className="text-sm text-slate-500 animate-pulse">Syncing...</span>}
                </div>
                <AlertToolbar
                    filter={filter}
                    onChange={updateFilter}
                    shown={filteredAlerts.length}
                    total={shownAlerts.length}
                    searchId={SEARCH_INPUT_ID}
                />
                <AlertTable
                    alerts={filteredAlerts}
                    onTriage={handleTriage}
                    onBlock={handleBlock}
                    blockedIps={blockedIps}
                />
            </div>

            <Toasts toasts={toasts} onDismiss={dismissToast} />
        </div>
    );
}
