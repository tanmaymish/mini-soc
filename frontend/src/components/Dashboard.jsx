import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import axios from 'axios';
import {
    Activity, ShieldCheck, Cpu, GitBranch, LayoutDashboard,
    Bell, ScanLine, Workflow, Gamepad2, Globe,
} from 'lucide-react';
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
import DefenseHUD from './DefenseHUD';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import SectionHeader from './SectionHeader';
import { getDemoAlerts, getDemoMitigations } from '../demoData';
import { ATTACK_KEYS, buildAttack, benignLog, correlateAlerts, randomAttackKey } from '../simEngine';
import {
    STATUS_NEW, STATUS_ACK, STATUS_RESOLVED, STATUS_META, CLOSED_STATUSES,
    normStatus, isOpen, alertKey,
} from '../alertStatus';
import {
    DEFENSE_DAMAGE, CONTAINS_PER_WAVE, scoreFor, breachWindow, spawnDelay, initialDefense,
} from '../defenseGame';

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
    const [view, setView] = useState('overview');   // active console section

    // SOC Defense (game mode): live threats each carry a breach countdown.
    const [defense, setDefense] = useState(initialDefense);
    const [threats, setThreats] = useState({});   // alertKey → { key, at, start, sev, ip, rule }
    const [gameNow, setGameNow] = useState(0);
    const [breachFlash, setBreachFlash] = useState(false);

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

    // Alerts the analyst has closed — used by the defense reconciler.
    const closedKeys = useMemo(() => {
        const s = new Set();
        for (const [k, t] of Object.entries(triage)) {
            if (CLOSED_STATUSES.has(t.status)) s.add(k);
        }
        return s;
    }, [triage]);

    // Refs so the game's timers read the latest state without re-subscribing.
    const threatsRef = useRef(threats); threatsRef.current = threats;
    const closedKeysRef = useRef(closedKeys); closedKeysRef.current = closedKeys;
    const blockedIpsRef = useRef(blockedIps); blockedIpsRef.current = blockedIps;
    const alertsRef = useRef(alerts); alertsRef.current = alerts;
    const waveRef = useRef(1); waveRef.current = defense.wave;
    const defenseActiveRef = useRef(false); defenseActiveRef.current = defense.active;

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

    // --- SOC Defense (game mode) -------------------------------------------

    // Spawn a threat: like a normal attack, but with a breach deadline and
    // NO auto-mitigation — containing it is now the analyst's job.
    const spawnDefenseThreat = useCallback(() => {
        const { alerts: a, logs: l } = buildAttack(randomAttackKey());
        setAlerts((prev) => [...a, ...prev].slice(0, 50));
        pushLogs(l);
        bucketHits.current += a.length;
        const now = Date.now();
        const win = breachWindow(waveRef.current);
        setThreats((prev) => {
            const next = { ...prev };
            for (const al of a) {
                const key = alertKey(al);
                next[key] = { key, at: now + win, start: now, sev: al.severity, ip: al.source_ip, rule: al.rule_name };
            }
            return next;
        });
    }, [pushLogs]);

    const startDefense = useCallback(() => {
        setAlerts([]);
        setMitigations([]);
        setManualMitigations([]);
        setTriage({});
        setLogs([]);
        setThreats({});
        setFilter({ sev: 'all', status: 'all', q: '' });
        setLiveFire(false);
        setDefense({ ...initialDefense(), active: true });
        addToast('SOC Defense engaged — contain every threat before it breaches!', 'attack');
    }, [addToast]);

    const endDefense = useCallback(() => {
        setThreats({});
        setDefense((prev) => ({ ...prev, active: false, over: true }));
    }, []);

    const dismissDefense = useCallback(() => {
        setThreats({});
        setDefense(initialDefense());
    }, []);

    // One-click containment from the HUD queue: block the source, close the alert.
    const defendThreat = useCallback((key) => {
        const alert = alertsRef.current.find((a) => alertKey(a) === key);
        if (!alert) return;
        handleBlock(alert);
        handleTriage(alert, STATUS_RESOLVED);
    }, [handleBlock, handleTriage]);

    // Game tick: the single owner of scoring. Every 250ms it reconciles the
    // pending threats — contained (closed or IP blocked) → score; expired →
    // breach + integrity damage; then advances waves / ends the game.
    useEffect(() => {
        if (!defense.active) return;
        const id = setInterval(() => {
            const now = Date.now();
            setGameNow(now);
            const cur = threatsRef.current;
            const contained = [];
            const breached = [];
            for (const [k, t] of Object.entries(cur)) {
                if (closedKeysRef.current.has(k) || blockedIpsRef.current.has(t.ip)) contained.push(t);
                else if (t.at <= now) breached.push(t);
            }
            if (!contained.length && !breached.length) return;

            setThreats((prev) => {
                const next = { ...prev };
                for (const t of [...contained, ...breached]) delete next[t.key];
                return next;
            });

            const dmg = breached.reduce((s, t) => s + (DEFENSE_DAMAGE[t.sev] || 8), 0);
            setDefense((prev) => {
                if (!prev.active) return prev;
                let { combo, score, contained: cc, breached: bb, integrity } = prev;
                for (const t of contained) { combo += 1; score += scoreFor(t.sev, combo); cc += 1; }
                if (breached.length) { combo = 0; bb += breached.length; integrity = Math.max(0, integrity - dmg); }
                const over = integrity <= 0;
                return {
                    ...prev, combo, score, contained: cc, breached: bb, integrity,
                    wave: 1 + Math.floor(cc / CONTAINS_PER_WAVE),
                    over, active: over ? false : prev.active,
                };
            });

            if (breached.length) {
                setBreachFlash(true);
                setTimeout(() => setBreachFlash(false), 350);
                addToast(`⚠ ${breached.length} threat(s) breached the perimeter — −${dmg}% integrity`, 'block');
            }
        }, 250);
        return () => clearInterval(id);
    }, [defense.active, addToast]);

    // Spawn loop — cadence tightens as waves escalate (reads waveRef live).
    useEffect(() => {
        if (!DEMO_MODE || !defense.active) return;
        let t;
        const schedule = () => {
            t = setTimeout(() => { spawnDefenseThreat(); schedule(); }, spawnDelay(waveRef.current));
        };
        spawnDefenseThreat();
        schedule();
        return () => clearTimeout(t);
    }, [defense.active, spawnDefenseThreat]);

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

            const k = e.key.toLowerCase();
            if (k === 'd') {
                defenseActiveRef.current ? endDefense() : startDefense();
                return;
            }
            // While a defense shift is live, mute the manual-attack keys so the
            // analyst can't self-inflict — only D (end) and R (abort) apply.
            if (defenseActiveRef.current) {
                if (k === 'r') endDefense();
                return;
            }
            if (/^[0-9]$/.test(e.key)) {
                const idx = e.key === '0' ? 9 : Number(e.key) - 1;
                if (ATTACK_KEYS[idx]) launchAttack(ATTACK_KEYS[idx]);
            } else if (k === 'u') {
                unleashAll();
            } else if (k === 'r') {
                resetBoard();
            } else if (k === 'l') {
                toggleLiveFire();
            }
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [launchAttack, unleashAll, resetBoard, toggleLiveFire, startDefense, endDefense]);

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

    // Global search jumps to the alert queue and filters it.
    const searchAlerts = useCallback((q) => {
        setFilter((prev) => ({ ...prev, q }));
        setView((v) => (q && v !== 'alerts' ? 'alerts' : v));
    }, []);

    const NAV = [
        { key: 'overview', label: 'Overview', icon: LayoutDashboard },
        {
            key: 'alerts', label: 'Alerts', icon: Bell, badge: openAlerts.length,
            badgeTone: criticalCount > 0 ? 'bg-red-500/20 text-red-300' : 'bg-slate-700 text-slate-300',
        },
        {
            key: 'incidents', label: 'Incidents', icon: GitBranch, badge: incidents.length,
            badgeTone: incidents.length ? 'bg-red-500/20 text-red-300' : 'bg-slate-700 text-slate-300',
        },
        { key: 'detections', label: 'Detections', icon: ScanLine },
        {
            key: 'automation', label: 'Automation', icon: Workflow, badge: allMitigations.length,
            badgeTone: 'bg-emerald-500/20 text-emerald-300',
        },
    ];
    if (DEMO_MODE) NAV.push({ key: 'simulation', label: 'Simulation', icon: Gamepad2 });

    const VIEW_META = {
        overview: { title: 'Overview', subtitle: 'Real-time security posture across the monitored estate' },
        alerts: { title: 'Alert Queue', subtitle: 'Triage, investigate and contain detections' },
        incidents: { title: 'Incidents', subtitle: 'Correlated multi-stage attacks stitched into kill-chains' },
        detections: { title: 'Detections', subtitle: 'Rule engine and API attack surface' },
        automation: { title: 'Automation', subtitle: 'SOAR playbooks and containment actions' },
        simulation: { title: 'Simulation & Training', subtitle: 'Generate telemetry and run defense drills' },
    };
    const meta = VIEW_META[view] || VIEW_META.overview;

    return (
        <div className="flex h-screen overflow-hidden">
            {breachFlash && <div className="breach-flash" />}

            <Sidebar items={NAV} active={view} onSelect={setView} demoMode={DEMO_MODE} error={error} />

            <div className="flex-1 min-w-0 flex flex-col h-screen">
                <TopBar
                    title={meta.title}
                    query={filter.q}
                    onQuery={searchAlerts}
                    searchId={SEARCH_INPUT_ID}
                    demoMode={DEMO_MODE}
                    error={error}
                    items={NAV}
                    active={view}
                    onSelect={setView}
                />

                <main className="flex-1 overflow-y-auto">
                    <div className="p-5 lg:p-8 max-w-[1600px] w-full mx-auto">
                        {/* SOC Defense HUD persists across views while a drill runs */}
                        {DEMO_MODE && (
                            <DefenseHUD
                                defense={defense}
                                threats={threats}
                                now={gameNow}
                                onContain={defendThreat}
                                onEnd={endDefense}
                                onRestart={startDefense}
                                onClose={dismissDefense}
                            />
                        )}

                        {error && !DEMO_MODE && (
                            <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3">
                                <Activity className="h-5 w-5" />
                                {error} Ensure Flask is running on port 5000.
                            </div>
                        )}

                        {/* ---- Overview ---- */}
                        {view === 'overview' && (
                            <>
                                <SectionHeader icon={LayoutDashboard} title={meta.title} subtitle={meta.subtitle} />
                                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5 mb-6">
                                    <StatCard title="Total Events Analyzed" value={eventsAnalyzed.toLocaleString()} type="info" />
                                    <StatCard title="Open Alerts" value={openAlerts.length} type="warning" />
                                    <StatCard title="Critical / High Threats" value={criticalCount} type={criticalCount > 0 ? 'critical' : ''} />
                                    <StatCard
                                        title={perf.closed > 0 ? `Analyst MTTR · ${perf.closed} closed` : 'Analyst MTTR'}
                                        value={fmtDur(perf.mttr)}
                                        sub={perf.mtta != null ? `MTTA ${fmtDur(perf.mtta)}` : null}
                                    />
                                </div>
                                <LiveAttackMap alerts={alerts} />
                                <ThreatCharts alerts={alerts} timeline={timeline} />
                                <RiskActors alerts={alerts} />
                            </>
                        )}

                        {/* ---- Alerts ---- */}
                        {view === 'alerts' && (
                            <>
                                <SectionHeader icon={Bell} title={meta.title} subtitle={meta.subtitle}>
                                    {loading && <span className="text-sm text-slate-500 animate-pulse">Syncing…</span>}
                                </SectionHeader>
                                <AlertToolbar
                                    filter={filter}
                                    onChange={updateFilter}
                                    shown={filteredAlerts.length}
                                    total={shownAlerts.length}
                                />
                                <AlertTable
                                    alerts={filteredAlerts}
                                    onTriage={handleTriage}
                                    onBlock={handleBlock}
                                    blockedIps={blockedIps}
                                    deadlines={threats}
                                    now={gameNow}
                                />
                            </>
                        )}

                        {/* ---- Incidents ---- */}
                        {view === 'incidents' && (
                            <>
                                <SectionHeader icon={GitBranch} title={meta.title} subtitle={meta.subtitle}>
                                    {incidents.length > 0 && (
                                        <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded font-bold border border-red-500/30">
                                            {incidents.length} ACTIVE
                                        </span>
                                    )}
                                </SectionHeader>
                                <IncidentsPanel incidents={incidents} />
                            </>
                        )}

                        {/* ---- Detections ---- */}
                        {view === 'detections' && (
                            <>
                                <SectionHeader icon={ScanLine} title={meta.title} subtitle={meta.subtitle} />
                                <DetectionRules alerts={alerts} />
                                <div className="mt-6">
                                    <ApiMapPanel />
                                </div>
                            </>
                        )}

                        {/* ---- Automation ---- */}
                        {view === 'automation' && (
                            <>
                                <SectionHeader icon={Workflow} title={meta.title} subtitle={meta.subtitle}>
                                    {allMitigations.length > 0 && (
                                        <span className="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-1 rounded font-bold border border-emerald-500/30">
                                            {allMitigations.length} APPLIED
                                        </span>
                                    )}
                                </SectionHeader>
                                <PlaybooksPanel mitigations={allMitigations} />
                                <div className="mt-8">
                                    <h2 className="text-base font-bold text-emerald-400 flex items-center gap-2 mb-4">
                                        <Cpu className="h-5 w-5 text-emerald-400" />
                                        Active SOAR Mitigations
                                    </h2>
                                    <MitigationTable mitigations={allMitigations} />
                                </div>
                            </>
                        )}

                        {/* ---- Simulation & Training (demo only) ---- */}
                        {view === 'simulation' && DEMO_MODE && (
                            <>
                                <SectionHeader icon={Gamepad2} title={meta.title} subtitle={meta.subtitle} />
                                <AttackSimulator
                                    onAttack={launchAttack}
                                    onUnleash={unleashAll}
                                    onReset={resetBoard}
                                    running={running}
                                    liveFire={liveFire}
                                    onToggleLiveFire={toggleLiveFire}
                                    defenseActive={defense.active}
                                    onDefense={startDefense}
                                />
                                <LiveConsole lines={logs} />
                            </>
                        )}
                    </div>
                </main>
            </div>

            <Toasts toasts={toasts} onDismiss={dismissToast} />
        </div>
    );
}
