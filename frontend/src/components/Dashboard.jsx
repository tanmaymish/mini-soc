import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, ShieldCheck, Radar, Cpu } from 'lucide-react';
import StatCard from './StatCard';
import AlertTable from './AlertTable';
import MitigationTable from './MitigationTable'; // NEW

const API_BASE = import.meta.env.VITE_API_BASE_URL ||
    (window.location.hostname === 'localhost' ? 'http://localhost:5000/api' : '/api');

export default function Dashboard() {
    const [alerts, setAlerts] = useState([]);
    const [mitigations, setMitigations] = useState([]); // NEW
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [stats, setStats] = useState({
        totalLogs: 0,
        totalAlerts: 0,
        criticalCount: 0
    });

    const fetchData = async () => {
        try {
            const [alertRes, mitigRes] = await Promise.all([
                axios.get(`${API_BASE}/alerts`),
                axios.get(`${API_BASE}/mitigations`)
            ]);

            const alertData = alertRes.data.alerts; // FIX: using the correct nested property
            const sortedAlerts = alertData.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            setAlerts(sortedAlerts);

            const mitigData = mitigRes.data;
            setMitigations(mitigData);

            const criticalCount = sortedAlerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;

            setStats({
                totalLogs: '10,245',
                totalAlerts: sortedAlerts.length,
                criticalCount: criticalCount
            });

            setError(null);
        } catch (err) {
            console.error("Error fetching SOC data:", err);
            setError("Failed to connect to SOAR API.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="p-8 max-w-7xl mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-3">
                    <div className="bg-brand-500/20 p-2 rounded-lg border border-brand-500/30">
                        <Radar className="h-8 w-8 text-brand-500" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Mini SOC Console</h1>
                        <p className="text-slate-400 text-sm">AI-Powered Threat Detection & SOAR Defense</p>
                    </div>
                </div>

                <div className="flex items-center gap-2 bg-slate-800 px-4 py-2 rounded-full border border-slate-700 shadow-sm">
                    <span className="relative flex h-3 w-3">
                        {error ? (
                            <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
                        ) : (
                            <>
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                            </>
                        )}
                    </span>
                    <span className="text-sm font-medium text-slate-300">
                        {error ? 'SOAR Engine Offline' : 'SOAR Active (Polling)'}
                    </span>
                </div>
            </div>

            {error && (
                <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-4 rounded-lg mb-8 shadow-sm flex items-center gap-3">
                    <Activity className="h-5 w-5" />
                    {error} Ensure Flask is running on port 5000.
                </div>
            )}

            {/* Stats Row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <StatCard title="Total Events Analyzed" value={stats.totalLogs} type="info" />
                <StatCard title="Active Alerts" value={stats.totalAlerts} type="warning" />
                <StatCard title="Critcal / High Threats" value={stats.criticalCount} type={stats.criticalCount > 0 ? 'critical' : ''} />
            </div>

            {/* SOAR Mitigations Feed */}
            <div className="mb-12">
                <div className="mb-4 flex items-center justify-between">
                    <h2 className="text-lg font-bold text-emerald-400 flex items-center gap-2">
                        <Cpu className="h-5 w-5 text-emerald-400" />
                        Active SOAR Mitigations
                    </h2>
                    {mitigations.length > 0 && (
                        <span className="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-1 rounded font-bold border border-emerald-500/30">
                            {mitigations.length} BLOCK(S) APPLIED
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
