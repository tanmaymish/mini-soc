import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import axios from 'axios';
import { Activity, ShieldCheck, Radar, Cpu, FlaskConical, GitBranch } from 'lucide-react';
import StatCard from './StatCard';
import AlertTable from './AlertTable';
import MitigationTable from './MitigationTable';
import AttackSimulator from './AttackSimulator';
import ThreatCharts from './ThreatCharts';
import LiveConsole from './LiveConsole';
import IncidentsPanel from './IncidentsPanel';
import DetectionRules from './DetectionRules';
import ApiMapPanel from './ApiMapPanel';
import RiskActors from './RiskActors';
import PlaybooksPanel from './PlaybooksPanel';
import { getDemoAlerts, getDemoMitigations } from '../demoData';
import { ATTACK_KEYS, buildAttack, benignLog, correlateAlerts } from '../simEngine';

// Demo mode: interactive, self-contained build (e.g. GitHub Pages).
const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true';

const API_BASE = import.meta.env.VITE_API_BASE_URL ||
    (window.location.hostname === 'localhost' ? 'http://localhost:5000/api' : '/api');

const TIMELINE_BUCKETS = 24;
const clock = () => new Date().toLocaleTimeString('en-GB');
let _lid = 0;

function makeTimeline() {
    return Array.from({ length: TIMELINE_BUCKETS }, (_, i) => ({ t: '', count: 0, _k: i }));
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

    const bucketHits = useRef(0);

    // Demo: incidents are correlated client-side from the alerts on the board.
    // Live: they come from the backend's correlation engine.
    const demoIncidents = useMemo(
        () => (DEMO_MODE ? correlateAlerts(alerts) : []), [alerts]);
    const incidents = DEMO_MODE ? demoIncidents : liveIncidents;

    const pushLogs = useCallback((entries) => {
        const stamped = entries.map((e) => ({ ...e, id: `l${_lid++}`, time: clock() }));
        setLogs((prev) => [...prev, ...stamped].slice(-120));
        setEventsAnalyzed((n) => n + entries.length);
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
        setLogs([]);
        setTimeline(makeTimeline());
        bucketHits.current = 0;
    }, []);

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

    const criticalCount = alerts.filter((a) => a.severity === 'critical' || a.severity === 'high').length;

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
                />
            )}

            {/* Stats Row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <StatCard title="Total Events Analyzed" value={eventsAnalyzed.toLocaleString()} type="info" />
                <StatCard title="Active Alerts" value={alerts.length} type="warning" />
                <StatCard title="Critical / High Threats" value={criticalCount} type={criticalCount > 0 ? 'critical' : ''} />
            </div>

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
                <PlaybooksPanel mitigations={mitigations} />
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
                    {mitigations.length > 0 && (
                        <span className="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-1 rounded font-bold border border-emerald-500/30">
                            {mitigations.length} ACTION(S) APPLIED
                        </span>
                    )}
                </div>
                <MitigationTable mitigations={mitigations} />
            </div>

            {/* Threat Alert Feed */}
            <div>
                <div className="mb-4 flex items-center justify-between">
                    <h2 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5 text-slate-400" />
                        Threat Alert Feed
                    </h2>
                    {loading && <span className="text-sm text-slate-500 animate-pulse">Syncing...</span>}
                </div>
                <AlertTable alerts={alerts} />
            </div>
        </div>
    );
}
