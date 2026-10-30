"""
Network Log Analyzer - Core Threat Detection & Forensic Analysis Engine
Author: Senior Cybersecurity Engineer
Course: Network Security & Forensics (NSF)
"""

import io
import re
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from config import (
    THRESHOLDS,
    PORT_MAPPING,
    WEB_ATTACK_SIGNATURES,
    THREAT_INTEL_BLACKLIST,
    SEVERITY_LEVELS,
    INCIDENT_PLAYBOOK
)

# Standard Regex pattern for Syslog/Firewall log lines
# Example: 2026-09-10 18:30:15 192.168.1.10:45123 -> 10.0.0.5:80 TCP ALLOW 200 4520 "HTTP GET /index.html"
LOG_LINE_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<source_ip>[0-9a-fA-F\.\:]+):(?P<source_port>\d+)\s+->\s+'
    r'(?P<destination_ip>[0-9a-fA-F\.\:]+):(?P<destination_port>\d+)\s+'
    r'(?P<protocol>[A-Z0-9]+)\s+'
    r'(?P<action>[A-Za-z]+)\s+'
    r'(?P<status_code>\d+)\s+'
    r'(?P<bytes_transferred>\d+)'
    r'(?:\s+"(?P<message>.*?)")?',
    re.MULTILINE
)


class LogAnalyzer:
    """Core Engine for parsing, analyzing, and detecting cyber attacks in network logs."""

    def __init__(self, thresholds=None):
        self.thresholds = thresholds if thresholds else THRESHOLDS.copy()
        self.df = pd.DataFrame()
        self.alerts = []
        self.metrics = {}

    def parse_logs(self, log_source):
        """
        Parses logs from file path, string content, or file-like buffer.
        Automatically detects CSV or Syslog/Raw text format.
        """
        raw_text = ""
        is_csv = False

        if isinstance(log_source, pd.DataFrame):
            self.df = self._normalize_csv_dataframe(log_source.copy())
            if not self.df.empty:
                self.df["service"] = self.df["destination_port"].map(PORT_MAPPING).fillna("Other / Unknown")
                self.df = self.df.sort_values(by="timestamp").reset_index(drop=True)
            return self.df

        if isinstance(log_source, str):
            if os.path.exists(log_source):
                with open(log_source, "r", encoding="utf-8", errors="ignore") as f:
                    sample = f.read(2048)
                    f.seek(0)
                    if "," in sample and ("timestamp" in sample.lower() or "source_ip" in sample.lower()):
                        is_csv = True
                        df = pd.read_csv(log_source)
                    else:
                        raw_text = f.read()
            else:
                raw_text = log_source
        elif hasattr(log_source, "read"):
            # File-like object (e.g. Streamlit UploadedFile)
            content = log_source.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="ignore")
            if "," in content[:1000] and ("timestamp" in content[:1000].lower() or "source_ip" in content[:1000].lower()):
                is_csv = True
                df = pd.read_csv(io.StringIO(content))
            else:
                raw_text = content
        else:
            raise ValueError("Unsupported log_source type. Must be file path, string, DataFrame, or file-like buffer.")

        if is_csv:
            self.df = self._normalize_csv_dataframe(df)
        else:
            self.df = self._parse_raw_text(raw_text)

        if not self.df.empty:
            self.df["service"] = self.df["destination_port"].map(PORT_MAPPING).fillna("Other / Unknown")
            self.df = self.df.sort_values(by="timestamp").reset_index(drop=True)

        return self.df

    def _normalize_csv_dataframe(self, df):
        """Ensures standard column names and types for CSV logs."""
        col_map = {
            "Time": "timestamp", "DateTime": "timestamp", "Timestamp": "timestamp",
            "SrcIP": "source_ip", "Source IP": "source_ip", "src_ip": "source_ip",
            "SrcPort": "source_port", "Source Port": "source_port", "src_port": "source_port",
            "DstIP": "destination_ip", "Destination IP": "destination_ip", "dst_ip": "destination_ip",
            "DstPort": "destination_port", "Destination Port": "destination_port", "dst_port": "destination_port",
            "Proto": "protocol", "Protocol": "protocol",
            "Action": "action",
            "Status": "status_code", "StatusCode": "status_code", "status": "status_code",
            "Bytes": "bytes_transferred", "Length": "bytes_transferred", "size": "bytes_transferred",
            "Message": "message", "Msg": "message", "info": "message"
        }
        df = df.rename(columns=col_map)
        
        # Ensure essential columns exist
        required_defaults = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": "0.0.0.0",
            "source_port": 0,
            "destination_ip": "0.0.0.0",
            "destination_port": 0,
            "protocol": "TCP",
            "action": "ALLOW",
            "status_code": 200,
            "bytes_transferred": 0,
            "message": ""
        }
        for col, default_val in required_defaults.items():
            if col not in df.columns:
                df[col] = default_val

        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce").fillna(pd.Timestamp.now())
        df["source_port"] = pd.to_numeric(df["source_port"], errors="coerce").fillna(0).astype(int)
        df["destination_port"] = pd.to_numeric(df["destination_port"], errors="coerce").fillna(0).astype(int)
        df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce").fillna(200).astype(int)
        df["bytes_transferred"] = pd.to_numeric(df["bytes_transferred"], errors="coerce").fillna(0).astype(int)
        df["message"] = df["message"].astype(str)
        return df

    def _parse_raw_text(self, text):
        """Extracts structured fields from raw text logs using regex."""
        records = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = LOG_LINE_PATTERN.match(line)
            if match:
                data = match.groupdict()
                records.append({
                    "timestamp": pd.to_datetime(data["timestamp"]),
                    "source_ip": data["source_ip"],
                    "source_port": int(data["source_port"]),
                    "destination_ip": data["destination_ip"],
                    "destination_port": int(data["destination_port"]),
                    "protocol": data["protocol"].upper(),
                    "action": data["action"].upper(),
                    "status_code": int(data["status_code"]),
                    "bytes_transferred": int(data["bytes_transferred"]),
                    "message": data["message"] if data["message"] else "",
                    "raw_log": line
                })
            else:
                # Fallback parser for generic space-delimited logs
                parts = line.split()
                if len(parts) >= 6:
                    records.append({
                        "timestamp": pd.to_datetime(parts[0] + " " + parts[1]) if len(parts) > 1 and ":" in parts[1] else pd.Timestamp.now(),
                        "source_ip": parts[2] if len(parts) > 2 else "0.0.0.0",
                        "source_port": 0,
                        "destination_ip": parts[3] if len(parts) > 3 else "0.0.0.0",
                        "destination_port": 80,
                        "protocol": "TCP",
                        "action": "UNKNOWN",
                        "status_code": 200,
                        "bytes_transferred": 0,
                        "message": " ".join(parts[4:]),
                        "raw_log": line
                    })
        return pd.DataFrame(records)

    def analyze(self):
        """Runs all detection heuristic modules and aggregates security alerts."""
        if self.df.empty:
            return {"alerts": [], "metrics": self._empty_metrics()}

        self.alerts = []
        
        # 1. Threat Intel / Blacklisted IPs Check
        self._detect_threat_intel_matches()

        # 2. Brute Force Detection
        self._detect_brute_force()

        # 3. Port Scan / Network Reconnaissance Detection
        self._detect_port_scan()

        # 4. Data Exfiltration / Bandwidth Anomaly Detection
        self._detect_data_exfiltration()

        # 5. Web Application Exploits (SQLi, XSS, Path Traversal, Command Injection)
        self._detect_web_attacks()

        # 6. Denial of Service (DoS / Flood) Detection
        self._detect_dos_floods()

        # Calculate Forensics Metrics Summary
        self.metrics = self._calculate_metrics()

        return {
            "alerts": self.alerts,
            "alerts_df": pd.DataFrame(self.alerts) if self.alerts else pd.DataFrame(),
            "metrics": self.metrics,
            "df": self.df
        }

    def _add_alert(self, timestamp, source_ip, destination_ip, destination_port, attack_type, severity, description, evidence, recommendation):
        """Helper to create standardized forensic alert objects."""
        self.alerts.append({
            "timestamp": timestamp if isinstance(timestamp, str) else timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "service": PORT_MAPPING.get(destination_port, f"Port {destination_port}"),
            "attack_type": attack_type,
            "severity": severity,
            "severity_score": SEVERITY_LEVELS.get(severity, {}).get("score", 1),
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation
        })

    def _detect_threat_intel_matches(self):
        """Checks if any connection involves known malicious threat-intel IPs."""
        for ip, intel in THREAT_INTEL_BLACKLIST.items():
            matches = self.df[(self.df["source_ip"] == ip) | (self.df["destination_ip"] == ip)]
            if not matches.empty:
                first_row = matches.iloc[0]
                self._add_alert(
                    timestamp=first_row["timestamp"],
                    source_ip=first_row["source_ip"],
                    destination_ip=first_row["destination_ip"],
                    destination_port=first_row["destination_port"],
                    attack_type="Blacklisted Malicious IP Access",
                    severity="CRITICAL",
                    description=f"Traffic involving known high-risk IOC: {ip} ({intel['reputation']}, Actor: {intel['threat_actor']}, Country: {intel['country']})",
                    evidence=f"Total {len(matches)} connection events detected matching Threat Intel Feed.",
                    recommendation="; ".join(INCIDENT_PLAYBOOK.get("Blacklisted Malicious IP Access", []))
                )

    def _detect_brute_force(self):
        """Identifies rapid repeated authentication failures from a single IP."""
        max_attempts = self.thresholds.get("brute_force_attempts", 4)
        window_sec = self.thresholds.get("brute_force_window_seconds", 60)

        # Filter for failed login indicators
        fail_condition = (
            (self.df["status_code"].isin([401, 403])) |
            (self.df["action"] == "BLOCK") |
            (self.df["message"].str.contains(r"failed|invalid|unauthorized|denied", case=False, na=False))
        )
        failed_df = self.df[fail_condition].copy()

        if failed_df.empty:
            return

        for src_ip, group in failed_df.groupby("source_ip"):
            if len(group) < max_attempts:
                continue
            group = group.sort_values("timestamp")
            
            # Sliding time-window check
            timestamps = group["timestamp"].tolist()
            for i in range(len(timestamps)):
                # Window range
                window_end = timestamps[i] + timedelta(seconds=window_sec)
                in_window = group[(group["timestamp"] >= timestamps[i]) & (group["timestamp"] <= window_end)]
                if len(in_window) >= max_attempts:
                    target_ip = in_window["destination_ip"].iloc[0]
                    target_port = in_window["destination_port"].iloc[0]
                    self._add_alert(
                        timestamp=timestamps[i],
                        source_ip=src_ip,
                        destination_ip=target_ip,
                        destination_port=target_port,
                        attack_type="Brute Force Attack",
                        severity="HIGH",
                        description=f"Detected {len(in_window)} failed authentication attempts within {window_sec}s from {src_ip} targeting {target_ip}:{target_port}",
                        evidence=f"Failed attempts: {len(in_window)} (Threshold: {max_attempts}). Sample msg: {in_window['message'].iloc[0]}",
                        recommendation="; ".join(INCIDENT_PLAYBOOK.get("Brute Force Attack", []))
                    )
                    break  # Avoid duplicate alerts for the same burst

    def _detect_port_scan(self):
        """Identifies rapid reconnaissance across multiple distinct ports from single IP."""
        unique_ports_thresh = self.thresholds.get("port_scan_unique_ports", 5)
        window_sec = self.thresholds.get("port_scan_window_seconds", 60)

        for src_ip, group in self.df.groupby("source_ip"):
            if group["destination_port"].nunique() < unique_ports_thresh:
                continue
            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].tolist()
            
            for i in range(len(timestamps)):
                window_end = timestamps[i] + timedelta(seconds=window_sec)
                in_window = group[(group["timestamp"] >= timestamps[i]) & (group["timestamp"] <= window_end)]
                distinct_ports = in_window["destination_port"].unique()
                
                if len(distinct_ports) >= unique_ports_thresh:
                    target_ip = in_window["destination_ip"].iloc[0]
                    ports_str = ", ".join(map(str, sorted(distinct_ports)[:10]))
                    if len(distinct_ports) > 10:
                        ports_str += f"... (+{len(distinct_ports)-10} more)"
                        
                    self._add_alert(
                        timestamp=timestamps[i],
                        source_ip=src_ip,
                        destination_ip=target_ip,
                        destination_port=0,
                        attack_type="Port Scanning / Reconnaissance",
                        severity="HIGH",
                        description=f"Host {src_ip} scanned {len(distinct_ports)} distinct ports on {target_ip} within {window_sec} seconds",
                        evidence=f"Probed ports: [{ports_str}]. Total connection attempts: {len(in_window)}",
                        recommendation="; ".join(INCIDENT_PLAYBOOK.get("Port Scanning / Reconnaissance", []))
                    )
                    break

    def _detect_data_exfiltration(self):
        """Flags unusually large single transfers or cumulative outbound data spikes."""
        single_threshold = self.thresholds.get("high_bandwidth_bytes", 5 * 1024 * 1024)
        exfil_total_threshold = self.thresholds.get("exfiltration_total_bytes", 20 * 1024 * 1024)

        # Check 1: Single massive transfer
        massive_transfers = self.df[self.df["bytes_transferred"] >= single_threshold]
        for _, row in massive_transfers.iterrows():
            mb_size = round(row["bytes_transferred"] / (1024 * 1024), 2)
            self._add_alert(
                timestamp=row["timestamp"],
                source_ip=row["source_ip"],
                destination_ip=row["destination_ip"],
                destination_port=row["destination_port"],
                attack_type="Data Exfiltration / High Bandwidth Anomaly",
                severity="CRITICAL",
                description=f"Massive outbound data payload transfer detected: {mb_size} MB sent from {row['source_ip']} to {row['destination_ip']}",
                evidence=f"Bytes transferred: {row['bytes_transferred']:,} bytes (Threshold: {single_threshold:,} bytes). Action: {row['action']}",
                recommendation="; ".join(INCIDENT_PLAYBOOK.get("Data Exfiltration / High Bandwidth Anomaly", []))
            )

        # Check 2: Total cumulative volume per IP exceeding threshold
        ip_volume = self.df.groupby(["source_ip", "destination_ip"])["bytes_transferred"].sum().reset_index()
        cumulative_exfil = ip_volume[ip_volume["bytes_transferred"] >= exfil_total_threshold]
        for _, row in cumulative_exfil.iterrows():
            if not any(a["source_ip"] == row["source_ip"] and a["attack_type"].startswith("Data Exfiltration") for a in self.alerts):
                mb_total = round(row["bytes_transferred"] / (1024 * 1024), 2)
                first_ts = self.df[self.df["source_ip"] == row["source_ip"]]["timestamp"].min()
                self._add_alert(
                    timestamp=first_ts,
                    source_ip=row["source_ip"],
                    destination_ip=row["destination_ip"],
                    destination_port=443,
                    attack_type="Data Exfiltration / High Bandwidth Anomaly",
                    severity="HIGH",
                    description=f"Cumulative data volume anomaly: {mb_total} MB transferred from {row['source_ip']} to {row['destination_ip']}",
                    evidence=f"Total bytes transferred: {row['bytes_transferred']:,} bytes.",
                    recommendation="; ".join(INCIDENT_PLAYBOOK.get("Data Exfiltration / High Bandwidth Anomaly", []))
                )

    def _detect_web_attacks(self):
        """Scans request message and URI strings for SQLi, XSS, Path Traversal, and Command Injection."""
        for idx, row in self.df.iterrows():
            msg = str(row["message"])
            if not msg:
                continue

            for attack_category, patterns in WEB_ATTACK_SIGNATURES.items():
                for pattern in patterns:
                    if pattern.search(msg):
                        matched_snippet = pattern.search(msg).group(0)
                        severity = "CRITICAL" if attack_category in ["SQL Injection (SQLi)", "Command Injection"] else "MEDIUM"
                        self._add_alert(
                            timestamp=row["timestamp"],
                            source_ip=row["source_ip"],
                            destination_ip=row["destination_ip"],
                            destination_port=row["destination_port"],
                            attack_type=f"Web Application Attack ({attack_category})",
                            severity=severity,
                            description=f"{attack_category} pattern matched in payload destined for {row['destination_ip']}:{row['destination_port']}",
                            evidence=f"Signature snippet matched: '{matched_snippet}' in raw payload: '{msg[:120]}'",
                            recommendation="; ".join(INCIDENT_PLAYBOOK.get("Web Application Attack (SQLi / XSS / Traversal)", []))
                        )
                        break

    def _detect_dos_floods(self):
        """Identifies extreme request frequency bursts from single IP."""
        req_threshold = self.thresholds.get("dos_request_threshold", 40)
        window_sec = self.thresholds.get("dos_window_seconds", 30)

        for src_ip, group in self.df.groupby("source_ip"):
            if len(group) < req_threshold:
                continue
            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].tolist()
            
            for i in range(len(timestamps)):
                window_end = timestamps[i] + timedelta(seconds=window_sec)
                in_window = group[(group["timestamp"] >= timestamps[i]) & (group["timestamp"] <= window_end)]
                if len(in_window) >= req_threshold:
                    target_ip = in_window["destination_ip"].iloc[0]
                    self._add_alert(
                        timestamp=timestamps[i],
                        source_ip=src_ip,
                        destination_ip=target_ip,
                        destination_port=in_window["destination_port"].iloc[0],
                        attack_type="Denial of Service (DoS / Flood)",
                        severity="CRITICAL",
                        description=f"High-frequency request flood: {len(in_window)} requests within {window_sec}s from {src_ip}",
                        evidence=f"Request volume: {len(in_window)} reqs in {window_sec}s (Threshold: {req_threshold})",
                        recommendation="; ".join(INCIDENT_PLAYBOOK.get("Denial of Service (DoS / Flood)", []))
                    )
                    break

    def _calculate_metrics(self):
        """Generates comprehensive summary metrics for auditing and forensics dashboards."""
        total_logs = len(self.df)
        total_threats = len(self.alerts)
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        attack_type_counts = {}
        top_attackers = {}

        for alert in self.alerts:
            sev = alert["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            atk = alert["attack_type"]
            attack_type_counts[atk] = attack_type_counts.get(atk, 0) + 1

            sip = alert["source_ip"]
            top_attackers[sip] = top_attackers.get(sip, 0) + 1

        # Total data volume processed
        total_bytes = int(self.df["bytes_transferred"].sum()) if not self.df.empty else 0
        total_mb = round(total_bytes / (1024 * 1024), 2)

        # Unique entities
        unique_src_ips = self.df["source_ip"].nunique() if not self.df.empty else 0
        unique_dst_ips = self.df["destination_ip"].nunique() if not self.df.empty else 0

        # High risk score calculation (0 to 100)
        risk_score = 0
        if total_logs > 0:
            weighted_threat_sum = (
                severity_counts.get("CRITICAL", 0) * 4 +
                severity_counts.get("HIGH", 0) * 3 +
                severity_counts.get("MEDIUM", 0) * 2 +
                severity_counts.get("LOW", 0) * 1
            )
            risk_score = min(100, int((weighted_threat_sum / max(1, total_threats * 0.5 + 5)) * 25))

        return {
            "total_logs": total_logs,
            "total_threats": total_threats,
            "severity_counts": severity_counts,
            "attack_type_counts": attack_type_counts,
            "top_attackers": top_attackers,
            "total_megabytes": total_mb,
            "unique_source_ips": unique_src_ips,
            "unique_destination_ips": unique_dst_ips,
            "overall_risk_score": risk_score
        }

    def _empty_metrics(self):
        """Returns empty default metric structure."""
        return {
            "total_logs": 0,
            "total_threats": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "attack_type_counts": {},
            "top_attackers": {},
            "total_megabytes": 0,
            "unique_source_ips": 0,
            "unique_destination_ips": 0,
            "overall_risk_score": 0
        }


if __name__ == "__main__":
    import sys
    file_path = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/mixed_attacks.log"
    print(f"[*] Analyzing log file: {file_path}")
    analyzer = LogAnalyzer()
    df = analyzer.parse_logs(file_path)
    results = analyzer.analyze()

    print(f"\n================ SECURITY AUDIT SUMMARY ================")
    print(f"Total Logs Processed: {results['metrics']['total_logs']}")
    print(f"Total Threats Flagged: {results['metrics']['total_threats']}")
    print(f"Overall Network Risk Score: {results['metrics']['overall_risk_score']}/100")
    print(f"Severity Breakdown: {results['metrics']['severity_counts']}")
    print(f"\n[+] Detected Threat Events:")
    for idx, alert in enumerate(results['alerts'], 1):
        print(f"  {idx}. [{alert['severity']}] {alert['attack_type']} from {alert['source_ip']} -> {alert['destination_ip']}:{alert['destination_port']}")
        print(f"     Evidence: {alert['evidence']}")
