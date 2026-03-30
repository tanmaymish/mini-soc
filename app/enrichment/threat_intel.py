"""
Threat Intelligence Lookup Module.

Simulates querying external Threat Intel Platforms (TIPs) like
VirusTotal, AbuseIPDB, or CrowdStrike Falcon to enrich IPs.

In a production environment, this would:
1. Check a local fast-cache (Redis) to avoid rate limits.
2. If miss, make an async HTTP request to the TIP API.
3. Cache the result for 24-48 hours.
"""

import logging

logger = logging.getLogger("mini_soc.enrichment.ti")

# A mocked database of known bad IPs for demonstration.
MOCK_TI_DATABASE = {
    # e.g. A Tor Exit Node
    "185.220.101.1": {
        "reputation_score": 95,
        "tags": ["TOR_EXIT_NODE", "ANONYMIZER"]
    },
    # e.g. A known SSH brute forcer botnet
    "45.33.32.156": {
        "reputation_score": 88,
        "tags": ["BRUTE_FORCER", "BOTNET"]
    },
    # e.g. A known Web Scanner / Vulnerability Prober
    "104.244.72.100": {
        "reputation_score": 75,
        "tags": ["SCANNER", "MALICIOUS_CRAWLER"]
    }
}


def lookup_ip(ip_address: str) -> dict:
    """
    Looks up an IP address in the Threat Intel provider.

    Returns:
        A dictionary containing reputation details. 
        If clean, returns score 0 and empty tags.
    """
    if not ip_address:
        return {"reputation_score": 0, "tags": [], "provider": "mock_ti"}
        
    result = MOCK_TI_DATABASE.get(ip_address)
    if result:
        return {
            "reputation_score": result["reputation_score"],
            "tags": result["tags"],
            "provider": "mock_ti",
            "malicious": True
        }
    
    # Clean or unknown IP
    return {
        "reputation_score": 0,
        "tags": [],
        "provider": "mock_ti",
        "malicious": False
    }
