"""
Network Log Analyzer - Configuration & Threat Signatures
Author: Senior Cybersecurity Engineer
Course: Network Security & Forensics (NSF)
"""

import re

# Detection Thresholds (Adjustable for sensitivity tuning)
THRESHOLDS = {
    # Brute Force: Max failed logins allowed within the time window
    "brute_force_attempts": 4,
    "brute_force_window_seconds": 60,
    
    # Port Scan: Minimum distinct destination ports targeted within time window
    "port_scan_unique_ports": 5,
    "port_scan_window_seconds": 60,
    
    # Data Exfiltration: Spike threshold in bytes (e.g., > 5 MB per single session)
    "high_bandwidth_bytes": 5 * 1024 * 1024,  # 5 MB
    "exfiltration_total_bytes": 20 * 1024 * 1024, # 20 MB total per IP in window
    
    # DoS / Request Flood: Max requests from single source IP in time window
    "dos_request_threshold": 40,
    "dos_window_seconds": 30
}

# Standard Port Number to Service Mapping
PORT_MAPPING = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Mail)",
    143: "IMAP (Mail)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (File Sharing)",
    1433: "MS-SQL Database",
    1521: "Oracle DB",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt / Dev Web",
    8080: "HTTP-Proxy / Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# Web Application Attack Signatures (Regex Patterns)
WEB_ATTACK_SIGNATURES = {
    "SQL Injection (SQLi)": [
        re.compile(r"(\%27|\')\s*(OR|AND)\s*(\%27|\'|\d|\w+)\s*=\s*(\%27|\'|\d|\w+)", re.IGNORECASE),
        re.compile(r"\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT)\b", re.IGNORECASE),
        re.compile(r";\s*(DROP|ALTER|TRUNCATE|DELETE\s+FROM)\s+\w+", re.IGNORECASE),
        re.compile(r"\b(WAITFOR\s+DELAY|SLEEP\(\d+\)|BENCHMARK\(\d+)", re.IGNORECASE),
        re.compile(r"--\s*$", re.IGNORECASE)
    ],
    "Cross-Site Scripting (XSS)": [
        re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
        re.compile(r"(onload|onerror|onclick|onmouseover)\s*=", re.IGNORECASE),
        re.compile(r"(%3C|<)img\s+src=.*?(%3E|>)", re.IGNORECASE)
    ],
    "Directory / Path Traversal": [
        re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e/|\.\.%2f)", re.IGNORECASE),
        re.compile(r"/(etc/passwd|windows/system32|boot\.ini|etc/shadow)", re.IGNORECASE)
    ],
    "Command Injection": [
        re.compile(r"(;\s*(cat|ls|whoami|id|nc|bash|sh|cmd\.exe|powershell)\b)", re.IGNORECASE),
        re.compile(r"(\|\s*(cat|ls|whoami|id|nc|bash|sh|cmd\.exe|powershell)\b)", re.IGNORECASE),
        re.compile(r"(`.*?`)", re.IGNORECASE)
    ]
}

# Simulated Threat Intelligence Feed (Known Malicious / Tor / Command & Control IPs)
THREAT_INTEL_BLACKLIST = {
    "185.220.101.5": {"reputation": "Tor Exit Node", "country": "DE", "threat_actor": "Anonymous Tor Proxy"},
    "194.26.29.112": {"reputation": "Known Brute-Force Botnet", "country": "RU", "threat_actor": "Mirai Variant"},
    "45.155.205.233": {"reputation": "Reconnaissance Scanner", "country": "SC", "threat_actor": "ShadowServer Scan"},
    "103.203.57.18": {"reputation": "C2 Server / Malware Drop", "country": "VN", "threat_actor": "CobaltStrike C2"},
    "198.51.100.42": {"reputation": "Simulated Malicious External Host", "country": "US", "threat_actor": "APT Simulator"}
}

# Severity Score Color & Definitions
SEVERITY_LEVELS = {
    "CRITICAL": {"score": 4, "color": "#FF2B2B", "description": "Active Exploitation or High-Volume Exfiltration"},
    "HIGH": {"score": 3, "color": "#FF7518", "description": "Brute Force, Blacklisted IP Access, or Severe Recon"},
    "MEDIUM": {"score": 2, "color": "#FFD700", "description": "Port Scanning or Suspicious Web Payloads"},
    "LOW": {"score": 1, "color": "#00D26A", "description": "Single Failed Login or Minor Protocol Anomaly"},
    "INFORMATIONAL": {"score": 0, "color": "#4361EE", "description": "Normal Legitimate Network Traffic"}
}

# Incident Response Recommendations Playbook
INCIDENT_PLAYBOOK = {
    "Brute Force Attack": [
        "Enforce account lockout policy after 3-5 consecutive failed attempts.",
        "Implement Multi-Factor Authentication (MFA) across all administrative endpoints.",
        "Deploy Fail2ban / IP rate limiting on SSH and Web login portals.",
        "Temporarily block the attacking IP address on the perimeter firewall."
    ],
    "Port Scanning / Reconnaissance": [
        "Configure firewall drop rules for unsolicited SYN packets on closed ports.",
        "Implement Port Knocking or disable exposed legacy management ports.",
        "Enable IDS/IPS signatures (Suricata / Snort) to automatically blacklist active scanning IPs.",
        "Verify internal asset inventory to ensure unauthorized listening services are shut down."
    ],
    "Data Exfiltration / High Bandwidth Anomaly": [
        "Isolate the compromised internal host from the subnet immediately.",
        "Capture and inspect packet payloads (PCAP) to identify leaked data assets.",
        "Review outbound DLP (Data Loss Prevention) rules and block destination external IP.",
        "Audit user session credentials and check for unauthorized privilege escalation."
    ],
    "Web Application Attack (SQLi / XSS / Traversal)": [
        "Deploy and update Web Application Firewall (WAF) rules (e.g. ModSecurity/Cloudflare).",
        "Sanitize and validate all client input parameters using parameterized queries (Prepared Statements).",
        "Encode HTML outputs to neutralize XSS reflection.",
        "Restrict web server file permissions and disable execution in upload directories."
    ],
    "Blacklisted Malicious IP Access": [
        "Block the IP address at the perimeter firewall / border gateway router.",
        "Correlate threat intel IOCs across enterprise SIEM to check for lateral movement.",
        "Inspect internal endpoint logs for secondary payload execution."
    ],
    "Denial of Service (DoS / Flood)": [
        "Enable SYN Cookies and TCP rate limiting on load balancers.",
        "Engage DDoS mitigation scrubbers / CDN upstream protection.",
        "Drop volumetric traffic from offending subnet at border routers."
    ]
}
