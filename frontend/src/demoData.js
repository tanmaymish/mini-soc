/**
 * Demo Mode dataset.
 *
 * Used when the dashboard is built with VITE_DEMO_MODE=true (e.g. the
 * GitHub Pages deployment, which has no backend attached). Timestamps
 * are generated relative to "now" on every load so the feed always
 * looks live.
 */

const minutesAgo = (m) => new Date(Date.now() - m * 60_000).toISOString();

const evt = (offsetMin, source_ip, action, port, user = null) => ({
    timestamp: minutesAgo(offsetMin),
    source_ip,
    source_port: 51000 + Math.floor(Math.random() * 900),
    destination_ip: '10.0.0.1',
    destination_port: port,
    action,
    user,
});

export function getDemoAlerts() {
    return [
        {
            _id: 'demo-web-1',
            rule_name: 'web_attack',
            severity: 'critical',
            source_ip: '45.155.205.99',
            status: 'new',
            timestamp: minutesAgo(2),
            created_at: minutesAgo(2),
            description:
                'Web attack from 45.155.205.99: SQL Injection, Scanner: sqlmap. GET /products?id=1 UNION SELECT username,password FROM users',
            mitre: { technique: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
            metadata: {
                categories: ['SQL Injection', 'Scanner: sqlmap'],
                http_method: 'GET',
                url: '/products?id=1 UNION SELECT username,password FROM users',
                status: 500,
                user_agent: 'sqlmap/1.7',
            },
            evidence: [evt(2, '45.155.205.99', 'WEB_REQUEST', 443)],
        },
        {
            _id: 'demo-ti-1',
            rule_name: 'threat_intel_match',
            severity: 'critical',
            source_ip: '185.220.101.1',
            status: 'new',
            timestamp: minutesAgo(4),
            created_at: minutesAgo(4),
            description:
                'Traffic from 185.220.101.1 matches a known threat actor on the Threat Intelligence Platform (score 95/100).',
            context:
                'IP found in Threat Intelligence Platform. Reputation Score: 95. Tags: [TOR_EXIT_NODE, ANONYMIZER]',
            mitre: { technique: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
            metadata: {
                reputation_score: 95,
                tags: ['TOR_EXIT_NODE', 'ANONYMIZER'],
                provider: 'mock_ti',
            },
            evidence: [evt(4, '185.220.101.1', 'FAILED_LOGIN', 22, 'valid_user')],
        },
        {
            _id: 'demo-bf-1',
            rule_name: 'brute_force_ssh',
            severity: 'high',
            source_ip: '192.168.1.100',
            status: 'new',
            timestamp: minutesAgo(9),
            created_at: minutesAgo(9),
            description:
                "Brute force attack detected: 5 failed login attempts for user 'root' from 192.168.1.100 within 60 seconds.",
            mitre: { technique: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
            metadata: { threshold: 5, window_seconds: 60, targeted_user: 'root' },
            evidence: [0, 1, 2, 3, 4].map((i) =>
                evt(9 + i * 0.02, '192.168.1.100', 'FAILED_LOGIN', 22, 'root')
            ),
        },
        {
            _id: 'demo-ps-1',
            rule_name: 'port_scan',
            severity: 'high',
            source_ip: '203.0.113.50',
            status: 'new',
            timestamp: minutesAgo(17),
            created_at: minutesAgo(17),
            description:
                'Horizontal port scan detected: 203.0.113.50 probed 10 distinct ports within 30 seconds.',
            mitre: { technique: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
            metadata: {
                unique_ports: [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 21, 25],
            },
            evidence: [22, 80, 443, 3306, 6379].map((p, i) =>
                evt(17 + i * 0.05, '203.0.113.50', 'BLOCKED', p)
            ),
        },
        {
            _id: 'demo-pe-1',
            rule_name: 'privilege_escalation',
            severity: 'critical',
            source_ip: '10.20.30.40',
            status: 'new',
            timestamp: minutesAgo(26),
            created_at: minutesAgo(26),
            description:
                "Potential privilege escalation: User 'deploy' executed sudo command after 3 failed authentication attempt(s) within 300s.",
            mitre: { technique: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
            metadata: { user: 'deploy', failed_auth_count: 3 },
            evidence: [
                evt(27, '10.20.30.40', 'FAILED_LOGIN', 22, 'deploy'),
                evt(26.5, '10.20.30.40', 'FAILED_LOGIN', 22, 'deploy'),
                evt(26, '10.20.30.40', 'SUDO_COMMAND', null, 'deploy'),
            ],
        },
        {
            _id: 'demo-ml-1',
            rule_name: 'ml_behavioral_anomaly',
            severity: 'high',
            source_ip: '10.0.0.99',
            status: 'new',
            timestamp: minutesAgo(41),
            created_at: minutesAgo(41),
            description:
                'Machine Learning Anomaly: Activity from 10.0.0.99 is highly unusual compared to the historical baseline. Action: ACCEPTED_LOGIN, Time: Hour 3.',
            mitre: { technique: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
            metadata: {
                model: 'IsolationForest',
                features: {
                    hour_of_day: 3,
                    is_weekend: 0,
                    is_failed_login: 0,
                    velocity_60s: 14,
                    unique_ports_60s: 1,
                },
            },
            evidence: [0, 1, 2].map((i) =>
                evt(41 + i * 0.02, '10.0.0.99', 'ACCEPTED_LOGIN', 22, 'sysadmin')
            ),
        },
    ];
}

export function getDemoMitigations() {
    return [
        {
            _id: 'demo-mit-0',
            timestamp: minutesAgo(2),
            playbook: 'block_malicious_ip',
            action: 'BLOCK_IP',
            target: '45.155.205.99',
            reason: 'Auto-mitigation due to web_attack alert.',
            status: 'applied',
        },
        {
            _id: 'demo-mit-1',
            timestamp: minutesAgo(4),
            playbook: 'block_malicious_ip',
            action: 'BLOCK_IP',
            target: '185.220.101.1',
            reason: 'Auto-mitigation due to threat_intel_match alert.',
            status: 'applied',
        },
        {
            _id: 'demo-mit-2',
            timestamp: minutesAgo(9),
            playbook: 'block_malicious_ip',
            action: 'BLOCK_IP',
            target: '192.168.1.100',
            reason: 'Auto-mitigation due to brute_force_ssh alert.',
            status: 'applied',
        },
        {
            _id: 'demo-mit-3',
            timestamp: minutesAgo(17),
            playbook: 'block_malicious_ip',
            action: 'BLOCK_IP',
            target: '203.0.113.50',
            reason: 'Auto-mitigation due to port_scan alert.',
            status: 'applied',
        },
        {
            _id: 'demo-mit-4',
            timestamp: minutesAgo(26),
            playbook: 'disable_compromised_user',
            action: 'DISABLE_USER',
            target: 'deploy',
            reason: 'Auto-mitigation due to privilege_escalation (Compromised Credentials).',
            status: 'applied',
        },
        {
            _id: 'demo-mit-5',
            timestamp: minutesAgo(41),
            playbook: 'block_malicious_ip',
            action: 'BLOCK_IP',
            target: '10.0.0.99',
            reason: 'Auto-mitigation due to ml_behavioral_anomaly alert.',
            status: 'applied',
        },
    ];
}
