"""
Unit Tests for Network Log Analyzer & Threat Detection Engine
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta
from analyzer import LogAnalyzer
from log_generator import NetworkLogGenerator
from report_generator import ForensicReportGenerator


@pytest.fixture
def sample_generator():
    return NetworkLogGenerator(start_time=datetime(2026, 9, 10, 10, 0, 0))


def test_parse_normal_log(sample_generator):
    analyzer = LogAnalyzer()
    logs = [sample_generator.generate_normal_log() for _ in range(10)]
    df = analyzer.parse_logs(pd.DataFrame(logs))
    
    assert len(df) == 10
    assert "source_ip" in df.columns
    assert "destination_ip" in df.columns
    assert "service" in df.columns


def test_detect_brute_force(sample_generator):
    analyzer = LogAnalyzer()
    normal_logs = [sample_generator.generate_normal_log() for _ in range(5)]
    brute_logs = sample_generator.generate_brute_force_attack(attempts=10)
    all_logs = normal_logs + brute_logs
    
    analyzer.parse_logs(pd.DataFrame(all_logs))
    results = analyzer.analyze()
    
    brute_alerts = [a for a in results["alerts"] if a["attack_type"] == "Brute Force Attack"]
    assert len(brute_alerts) >= 1
    assert brute_alerts[0]["source_ip"] == "194.26.29.112"
    assert brute_alerts[0]["severity"] == "HIGH"


def test_detect_port_scan(sample_generator):
    analyzer = LogAnalyzer()
    scan_logs = sample_generator.generate_port_scan_attack(num_ports=10)
    
    analyzer.parse_logs(pd.DataFrame(scan_logs))
    results = analyzer.analyze()
    
    scan_alerts = [a for a in results["alerts"] if "Port Scanning" in a["attack_type"]]
    assert len(scan_alerts) >= 1
    assert scan_alerts[0]["source_ip"] == "45.155.205.233"


def test_detect_data_exfiltration(sample_generator):
    analyzer = LogAnalyzer()
    exfil_logs = sample_generator.generate_data_exfiltration_attack()
    
    analyzer.parse_logs(pd.DataFrame(exfil_logs))
    results = analyzer.analyze()
    
    exfil_alerts = [a for a in results["alerts"] if "Data Exfiltration" in a["attack_type"]]
    assert len(exfil_alerts) >= 1
    assert exfil_alerts[0]["severity"] in ["CRITICAL", "HIGH"]


def test_detect_web_exploits(sample_generator):
    analyzer = LogAnalyzer()
    web_logs = sample_generator.generate_web_attacks()
    
    analyzer.parse_logs(pd.DataFrame(web_logs))
    results = analyzer.analyze()
    
    web_alerts = [a for a in results["alerts"] if "Web Application Attack" in a["attack_type"]]
    assert len(web_alerts) >= 3  # SQLi, XSS, Path Traversal, Cmd Inj


def test_detect_threat_intel_match(sample_generator):
    analyzer = LogAnalyzer()
    # 185.220.101.5 is in threat intel feed
    web_logs = sample_generator.generate_web_attacks()
    analyzer.parse_logs(pd.DataFrame(web_logs))
    results = analyzer.analyze()
    
    intel_alerts = [a for a in results["alerts"] if a["attack_type"] == "Blacklisted Malicious IP Access"]
    assert len(intel_alerts) >= 1


def test_pdf_report_generation(sample_generator):
    analyzer = LogAnalyzer()
    dataset = sample_generator.generate_dataset(normal_count=20, include_attacks=True)
    analyzer.parse_logs(pd.DataFrame(dataset))
    results = analyzer.analyze()
    
    rep_gen = ForensicReportGenerator(results)
    pdf_bytes = rep_gen.generate_pdf_report()
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 1000
    
    csv_str = rep_gen.export_csv()
    assert "timestamp,source_ip" in csv_str
