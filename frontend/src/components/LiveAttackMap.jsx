import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Globe2, Radio } from 'lucide-react';

/**
 * Live global attack map.
 *
 * Renders a generated dot-grid world (no external tiles/assets — CSP-safe for
 * GitHub Pages) and animates an arc from each attacker's geolocation to the
 * SOC, colored by severity. Reacts to new alerts on the board; also emits a
 * little ambient traffic so it always feels live.
 */

const W = 820, H = 400;
const project = (lat, lon) => ({ x: ((lon + 180) / 360) * W, y: ((90 - lat) / 180) * H });

// Coarse continent silhouettes as lon/lat ellipses → a recognizable dotted world.
const LAND = [
    [-100, 46, 30, 20], [-90, 15, 12, 7], [-60, -20, 15, 26], [-42, 72, 12, 7],
    [15, 50, 18, 12], [22, 3, 22, 28], [45, 30, 12, 9],
    [90, 62, 55, 14], [100, 40, 34, 16], [78, 22, 11, 12], [110, 6, 15, 11],
    [134, -25, 16, 11],
];
const inLand = (lon, lat) => LAND.some(([cx, cy, rx, ry]) =>
    ((lon - cx) / rx) ** 2 + ((lat - cy) / ry) ** 2 <= 1);

// SOC HQ (Ashburn, VA — datacenter alley).
const HQ = { lat: 39, lon: -77.5, name: 'SOC HQ' };

const CITIES = {
    moscow: { lat: 55.75, lon: 37.62, name: 'Moscow, RU' },
    frankfurt: { lat: 50.1, lon: 8.68, name: 'Frankfurt, DE' },
    amsterdam: { lat: 52.37, lon: 4.9, name: 'Amsterdam, NL' },
    kyiv: { lat: 50.45, lon: 30.52, name: 'Kyiv, UA' },
    bucharest: { lat: 44.43, lon: 26.1, name: 'Bucharest, RO' },
    beijing: { lat: 39.9, lon: 116.4, name: 'Beijing, CN' },
    singapore: { lat: 1.35, lon: 103.8, name: 'Singapore, SG' },
    mumbai: { lat: 19.07, lon: 72.87, name: 'Mumbai, IN' },
    tehran: { lat: 35.7, lon: 51.4, name: 'Tehran, IR' },
    saopaulo: { lat: -23.5, lon: -46.6, name: 'São Paulo, BR' },
    lagos: { lat: 6.5, lon: 3.4, name: 'Lagos, NG' },
};
const CITY_KEYS = Object.keys(CITIES);

const PREFIX_GEO = [
    ['185.220.101', 'frankfurt'], ['185.220.55', 'frankfurt'], ['45.155.205', 'moscow'],
    ['194.32.122', 'moscow'], ['45.83', 'bucharest'], ['91.219.29', 'kyiv'],
    ['91.240.118', 'bucharest'], ['203.0.113', 'singapore'], ['45.33', 'beijing'],
];

function geoForIP(ip) {
    if (!ip) return { ...CITIES.singapore, internal: false };
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) {
        return { lat: HQ.lat + 2, lon: HQ.lon - 6, name: `Internal ${ip}`, internal: true };
    }
    for (const [pfx, key] of PREFIX_GEO) if (ip.startsWith(pfx)) return CITIES[key];
    let h = 0;
    for (const c of ip) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return CITIES[CITY_KEYS[h % CITY_KEYS.length]];
}

const SEV_COLOR = { critical: '#ef4444', high: '#f59e0b', medium: '#eab308', low: '#3b82f6', info: '#3b82f6' };

let _aid = 0;

export default function LiveAttackMap({ alerts }) {
    const dots = useMemo(() => {
        const pts = [];
        for (let lon = -180; lon <= 180; lon += 4) {
            for (let lat = -56; lat <= 78; lat += 4) {
                if (inLand(lon, lat)) pts.push(project(lat, lon));
            }
        }
        return pts;
    }, []);

    const hq = project(HQ.lat, HQ.lon);
    const [arcs, setArcs] = useState([]);
    const [feed, setFeed] = useState([]);
    const [count, setCount] = useState(0);
    const seen = useRef(new Set());
    const timers = useRef([]);

    const spawn = (ip, severity, label) => {
        const g = geoForIP(ip);
        const from = project(g.lat, g.lon);
        // Lift the control point for a nice arc.
        const mx = (from.x + hq.x) / 2;
        const my = (from.y + hq.y) / 2 - Math.hypot(hq.x - from.x, hq.y - from.y) * 0.28 - 12;
        const d = `M ${from.x} ${from.y} Q ${mx} ${my} ${hq.x} ${hq.y}`;
        const id = `arc${_aid++}`;
        const color = SEV_COLOR[severity] || SEV_COLOR.low;
        const arc = { id, d, from, color };
        setArcs((a) => [...a, arc]);
        setCount((c) => c + 1);
        setFeed((f) => [{ id, name: g.name, severity, label, color }, ...f].slice(0, 6));
        const t = setTimeout(() => setArcs((a) => a.filter((x) => x.id !== id)), 2200);
        timers.current.push(t);
    };

    // React to new alerts.
    useEffect(() => {
        for (const a of alerts) {
            const key = a._id || `${a.rule_name}-${a.timestamp}`;
            if (seen.current.has(key)) continue;
            seen.current.add(key);
            // Skip the very first bulk (seed) from stacking — still show a few.
            spawn(a.source_ip, a.severity, a.rule_name);
        }
    }, [alerts]); // eslint-disable-line react-hooks/exhaustive-deps

    // Ambient traffic so the map always has motion.
    useEffect(() => {
        const int = setInterval(() => {
            const ip = `${20 + Math.floor(Math.random() * 200)}.x`;
            spawn(ip, Math.random() > 0.7 ? 'medium' : 'low', 'recon');
        }, 2600);
        return () => { clearInterval(int); timers.current.forEach(clearTimeout); };
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    return (
        <div className="bg-slate-900/70 rounded-xl border border-slate-700 shadow-lg mb-8 overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                    <Globe2 className="h-5 w-5 text-brand-500" />
                    <h2 className="text-lg font-bold text-slate-100">Live Global Attack Map</h2>
                </div>
                <div className="flex items-center gap-3 text-xs">
                    <span className="text-slate-400 tabular-nums">{count} attacks tracked</span>
                    <span className="flex items-center gap-1.5 text-emerald-400 uppercase tracking-wider">
                        <Radio className="h-3.5 w-3.5 animate-pulse" /> live
                    </span>
                </div>
            </div>

            <div className="relative">
                <svg viewBox={`0 0 ${W} ${H}`} className="w-full block" style={{ background: 'radial-gradient(circle at 50% 40%, #0b1424, #060a15)' }}>
                    {/* world dots */}
                    {dots.map((p, i) => (
                        <circle key={i} cx={p.x} cy={p.y} r={1.1} fill="#1e3a5f" />
                    ))}

                    {/* active attack arcs + travelling projectile */}
                    {arcs.map((arc) => (
                        <g key={arc.id}>
                            <path d={arc.d} fill="none" stroke={arc.color} strokeWidth={1.3}
                                strokeOpacity={0.7} style={{ animation: 'arcFade 2.2s ease-out forwards' }} />
                            <circle r={2.5} fill="#fff" stroke={arc.color} strokeWidth={1}>
                                <animateMotion dur="1.4s" repeatCount="1" fill="freeze" path={arc.d} />
                            </circle>
                            {/* origin flash */}
                            <circle cx={arc.from.x} cy={arc.from.y} r={3} fill={arc.color}
                                style={{ animation: 'ping 2.2s ease-out forwards' }} />
                        </g>
                    ))}

                    {/* SOC HQ */}
                    <circle cx={hq.x} cy={hq.y} r={5} fill="#10b981" />
                    <circle cx={hq.x} cy={hq.y} r={5} fill="none" stroke="#10b981" strokeWidth={1.5}>
                        <animate attributeName="r" from="5" to="16" dur="2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite" />
                    </circle>
                    <text x={hq.x + 9} y={hq.y + 4} fill="#6ee7b7" fontSize="10" fontFamily="monospace">SOC HQ</text>
                </svg>

                {/* live threat feed overlay */}
                <div className="absolute top-3 left-3 space-y-1 pointer-events-none">
                    {feed.map((f) => (
                        <div key={f.id} className="flex items-center gap-2 bg-slate-950/70 backdrop-blur px-2 py-1 rounded text-[10px] font-mono border border-slate-800">
                            <span className="h-2 w-2 rounded-full" style={{ background: f.color }} />
                            <span className="text-slate-300">{f.name}</span>
                            <span className="text-slate-500">{f.label}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
