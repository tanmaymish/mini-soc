/**
 * Client-side attack simulation engine for the demo dashboard.
 *
 * Produces the same shapes the real backend emits (alerts, SOAR mitigations,
 * raw log lines) so visitors can "launch" attacks and watch the SOC react —
 * no server required. This is what makes the GitHub Pages demo interactive.
 */

let _seq = 0;
const uid = (p) => `${p}-${Date.now()}-${_seq++}`;
const nowISO = () => new Date().toISOString();
const rand = (n) => Math.floor(Math.random() * n);
const pick = (a) => a[rand(a.length)];

const MITRE = {
    brute_force_ssh: { technique: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
    port_scan: { technique: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
    privilege_escalation: { technique: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
    ml_behavioral_anomaly: { technique: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
    threat_intel_match: { technique: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
    web_attack: { technique: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
};

const evt = (ip, action, port, user) => ({
    timestamp: nowISO(),
    source_ip: ip,
    source_port: 40000 + rand(20000),
    destination_ip: '10.0.0.1',
    destination_port: port,
    action,
    user,
});

const alert = (rule, severity, ip, description, extra = {}) => ({
    _id: uid('a'),
    rule_name: rule,
    severity,
    source_ip: ip,
    status: 'new',
    timestamp: nowISO(),
    created_at: nowISO(),
    description,
    mitre: MITRE[rule],
    isNew: true,
    ...extra,
});

const block = (ip, rule) => ({
    _id: uid('m'),
    timestamp: nowISO(),
    playbook: 'block_malicious_ip',
    action: 'BLOCK_IP',
    target: ip,
    reason: `Auto-mitigation due to ${rule} alert.`,
    status: 'applied',
    isNew: true,
});

const disableUser = (user, rule) => ({
    _id: uid('m'),
    timestamp: nowISO(),
    playbook: 'disable_compromised_user',
    action: 'DISABLE_USER',
    target: user,
    reason: `Auto-mitigation due to ${rule} (Compromised Credentials).`,
    status: 'applied',
    isNew: true,
});

const randIP = (base) => `${base}.${1 + rand(253)}`;

// The catalog of attacks a visitor can launch.
export const ATTACKS = {
    brute_force: {
        label: 'SSH Brute Force',
        icon: 'KeyRound',
        color: 'orange',
        build() {
            const ip = randIP('192.168.1');
            const logs = Array.from({ length: 6 }, (_, i) => ({
                raw: `sshd[${12340 + i}]: Failed password for root from ${ip} port 22 ssh2`,
                kind: 'attack',
            }));
            return {
                logs,
                alerts: [alert('brute_force_ssh', 'high', ip,
                    `Brute force: 5+ failed root logins from ${ip} within 60s.`,
                    { evidence: [0, 1, 2, 3, 4].map(() => evt(ip, 'FAILED_LOGIN', 22, 'root')) })],
                mitigations: [block(ip, 'brute_force_ssh')],
            };
        },
    },
    port_scan: {
        label: 'Port Scan',
        icon: 'Radar',
        color: 'orange',
        build() {
            const ip = randIP('203.0.113');
            const ports = [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 21, 25];
            return {
                logs: ports.map((p) => ({
                    raw: `kernel: BLOCKED IN=eth0 SRC=${ip} DST=10.0.0.1 DPT=${p} PROTO=TCP`,
                    kind: 'attack',
                })),
                alerts: [alert('port_scan', 'high', ip,
                    `Horizontal port scan: ${ip} probed ${ports.length} distinct ports in 30s.`,
                    { evidence: ports.slice(0, 5).map((p) => evt(ip, 'BLOCKED', p)) })],
                mitigations: [block(ip, 'port_scan')],
            };
        },
    },
    sqli: {
        label: 'SQL Injection',
        icon: 'Database',
        color: 'red',
        build() {
            const ip = randIP('45.155.205');
            const url = "/products?id=1 UNION SELECT username,password FROM users";
            return {
                logs: [{ raw: `nginx: ${ip} "GET ${url}" 500 "sqlmap/1.7"`, kind: 'attack' }],
                alerts: [alert('web_attack', 'critical', ip,
                    `Web attack from ${ip}: SQL Injection, Scanner: sqlmap. GET ${url}`,
                    { metadata: { categories: ['SQL Injection', 'Scanner: sqlmap'], url, status: 500 },
                      evidence: [evt(ip, 'WEB_REQUEST', 443)] })],
                mitigations: [block(ip, 'web_attack')],
            };
        },
    },
    xss: {
        label: 'XSS Probe',
        icon: 'Code',
        color: 'yellow',
        build() {
            const ip = randIP('91.240.118');
            const url = "/search?q=<script>alert(document.cookie)</script>";
            return {
                logs: [{ raw: `nginx: ${ip} "GET ${url}" 200 "Mozilla/5.0"`, kind: 'attack' }],
                alerts: [alert('web_attack', 'high', ip,
                    `Web attack from ${ip}: Cross-Site Scripting (XSS). GET ${url}`,
                    { metadata: { categories: ['Cross-Site Scripting (XSS)'], url, status: 200 },
                      evidence: [evt(ip, 'WEB_REQUEST', 443)] })],
                mitigations: [block(ip, 'web_attack')],
            };
        },
    },
    threat_intel: {
        label: 'Known Bad IP',
        icon: 'Globe',
        color: 'red',
        build() {
            const ip = '185.220.101.1';
            return {
                logs: [{ raw: `sshd[999]: Connection from ${ip} (TOR_EXIT_NODE) port 22`, kind: 'attack' }],
                alerts: [alert('threat_intel_match', 'critical', ip,
                    `Traffic from ${ip} matches a known threat actor (score 95/100).`,
                    { context: 'IP found in Threat Intelligence Platform. Reputation Score: 95. Tags: [TOR_EXIT_NODE, ANONYMIZER]',
                      metadata: { reputation_score: 95, tags: ['TOR_EXIT_NODE', 'ANONYMIZER'] },
                      evidence: [evt(ip, 'FAILED_LOGIN', 22, 'valid_user')] })],
                mitigations: [block(ip, 'threat_intel_match')],
            };
        },
    },
    priv_esc: {
        label: 'Privilege Escalation',
        icon: 'UserCog',
        color: 'red',
        build() {
            const ip = randIP('10.20.30');
            const user = pick(['deploy', 'jenkins', 'www-data', 'ubuntu']);
            return {
                logs: [
                    { raw: `sshd: Failed password for ${user} from ${ip} port 22 ssh2`, kind: 'attack' },
                    { raw: `sudo: ${user} : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash`, kind: 'attack' },
                ],
                alerts: [alert('privilege_escalation', 'critical', ip,
                    `Privilege escalation: '${user}' ran sudo after failed auth from ${ip}.`,
                    { metadata: { user, failed_auth_count: 3 },
                      evidence: [evt(ip, 'FAILED_LOGIN', 22, user), evt(ip, 'SUDO_COMMAND', null, user)] })],
                mitigations: [disableUser(user, 'privilege_escalation')],
            };
        },
    },
    ml_anomaly: {
        label: 'ML Anomaly (3AM)',
        icon: 'Cpu',
        color: 'orange',
        build() {
            const ip = randIP('10.0.0');
            return {
                logs: Array.from({ length: 4 }, () => ({
                    raw: `sshd: Accepted publickey for sysadmin from ${ip} port 22 ssh2`,
                    kind: 'attack',
                })),
                alerts: [alert('ml_behavioral_anomaly', 'high', ip,
                    `ML anomaly: activity from ${ip} deviates from baseline (Hour 3, high velocity).`,
                    { metadata: { model: 'IsolationForest', features: { hour_of_day: 3, velocity_60s: 14 } },
                      evidence: [evt(ip, 'ACCEPTED_LOGIN', 22, 'sysadmin')] })],
                mitigations: [block(ip, 'ml_behavioral_anomaly')],
            };
        },
    },
};

export const ATTACK_KEYS = Object.keys(ATTACKS);

// Ambient benign traffic to keep the console + timeline alive.
const BENIGN = [
    () => `sshd: Accepted password for admin from 10.0.0.${20 + rand(30)} port 22 ssh2`,
    () => `nginx: 10.0.0.${20 + rand(30)} "GET /api/health" 200 "kube-probe/1.29"`,
    () => `nginx: 66.249.66.${rand(255)} "GET /robots.txt" 200 "Googlebot/2.1"`,
    () => `sshd: Accepted publickey for devops from 10.0.0.${20 + rand(30)} port 22 ssh2`,
    () => `nginx: 10.0.0.${20 + rand(30)} "POST /login" 200 "Mozilla/5.0"`,
    () => `systemd: Started Session ${rand(9999)} of user deploy.`,
];

export const benignLog = () => ({ raw: pick(BENIGN)(), kind: 'benign' });

export function buildAttack(key) {
    return ATTACKS[key].build();
}
