import React, { useMemo } from 'react';
import { Globe2 } from 'lucide-react';
import { geoForIP, SOC_GEO } from '../simEngine';

// Equirectangular projection into a 720×360 viewBox.
const W = 720, H = 360;
const project = (lon, lat) => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];

// Continents approximated as ellipses in (lon, lat) space — enough to render a
// recognizable dot-matrix world without shipping full coastline data.
const LAND = [
    [-100, 45, 34, 22], [-90, 27, 18, 14], [-140, 62, 18, 12], [-40, 72, 16, 8],  // N. America + Greenland
    [-60, -15, 17, 24],                                                             // S. America
    [15, 50, 24, 12], [30, 58, 18, 10],                                            // Europe
    [18, 2, 24, 33],                                                                // Africa
    [95, 48, 46, 22], [80, 22, 26, 18], [110, 30, 20, 22],                          // Asia
    [135, -25, 15, 11],                                                            // Australia
];
const inLand = (lon, lat) =>
    LAND.some(([cx, cy, rx, ry]) => ((lon - cx) / rx) ** 2 + ((lat - cy) / ry) ** 2 <= 1);

const LAND_DOTS = (() => {
    const dots = [];
    for (let lat = 78; lat >= -58; lat -= 4)
        for (let lon = -178; lon <= 178; lon += 4)
            if (inLand(lon, lat)) dots.push(project(lon, lat));
    return dots;
})();

const SEV_COLOR = { critical: '#ef4444', high: '#f59e0b', medium: '#eab308', low: '#38bdf8' };

export default function ThreatMap({ alerts }) {
    const origins = useMemo(() => {
        const by = {};
        for (const a of alerts) {
            const g = geoForIP(a.source_ip);
            if (!g) continue;
            const key = a.source_ip;
            if (!by[key]) by[key] = { ...g, ip: key, sev: a.severity, count: 0 };
            by[key].count += 1;
            // keep the most severe seen
            const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
            if ((rank[a.severity] || 0) > (rank[by[key].sev] || 0)) by[key].sev = a.severity;
        }
        return Object.values(by).slice(0, 40);
    }, [alerts]);

    const [hx, hy] = project(SOC_GEO.lon, SOC_GEO.lat);

    return (
        <div className="bg-slate-950 rounded-xl border border-slate-800 p-5 shadow-lg">
            <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                    <Globe2 className="h-5 w-5 text-brand-500" />
                    <h2 className="text-lg font-bold text-slate-100">Live Threat Map</h2>
                </div>
                <span className="text-xs bg-red-500/15 text-red-300 px-2 py-1 rounded font-bold border border-red-500/30">
                    {origins.length} ORIGIN(S)
                </span>
            </div>

            <div className="relative w-full overflow-hidden rounded-lg" style={{ background: 'radial-gradient(120% 120% at 50% 20%, #0b1220, #060a14)' }}>
                <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto block">
                    {/* land dot-matrix */}
                    {LAND_DOTS.map(([x, y], i) => (
                        <circle key={i} cx={x} cy={y} r="1.5" fill="#1e3a5f" />
                    ))}

                    {/* arcs from each origin to HQ */}
                    {origins.map((o) => {
                        const [x, y] = project(o.lon, o.lat);
                        const mx = (x + hx) / 2, my = Math.min(y, hy) - 40;
                        return (
                            <path key={'arc' + o.ip} d={`M ${x} ${y} Q ${mx} ${my} ${hx} ${hy}`}
                                fill="none" stroke={SEV_COLOR[o.sev] || '#38bdf8'} strokeOpacity="0.35" strokeWidth="1" />
                        );
                    })}

                    {/* HQ node */}
                    <circle cx={hx} cy={hy} r="4" fill="#22d3ee" />
                    <circle cx={hx} cy={hy} r="4" fill="none" stroke="#22d3ee" strokeWidth="1.5">
                        <animate attributeName="r" from="4" to="16" dur="2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite" />
                    </circle>
                    <text x={hx + 8} y={hy + 3} fill="#67e8f9" fontSize="10" fontFamily="monospace">SOC · HQ</text>

                    {/* attack origins — pulsing */}
                    {origins.map((o) => {
                        const [x, y] = project(o.lon, o.lat);
                        const c = SEV_COLOR[o.sev] || '#38bdf8';
                        return (
                            <g key={o.ip}>
                                <circle cx={x} cy={y} r="3.5" fill={c} />
                                <circle cx={x} cy={y} r="3.5" fill="none" stroke={c} strokeWidth="1.2">
                                    <animate attributeName="r" from="3.5" to="14" dur="1.8s" repeatCount="indefinite" />
                                    <animate attributeName="opacity" from="0.9" to="0" dur="1.8s" repeatCount="indefinite" />
                                </circle>
                            </g>
                        );
                    })}
                </svg>
            </div>

            {/* origin legend */}
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono max-h-16 overflow-y-auto">
                {origins.length === 0 && <span className="text-slate-600">No active origins — launch an attack.</span>}
                {origins.slice(0, 8).map((o) => (
                    <span key={o.ip} className="text-slate-400">
                        <span style={{ color: SEV_COLOR[o.sev] }}>●</span> {o.ip}
                        <span className="text-slate-600"> · {o.city} {o.cc}</span>
                    </span>
                ))}
            </div>
        </div>
    );
}
