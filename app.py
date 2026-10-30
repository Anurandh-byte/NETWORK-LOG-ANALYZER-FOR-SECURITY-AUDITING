"""
Network Log Analyzer for Security Auditing - Streamlit SOC Web Dashboard
Author: Senior Cybersecurity Engineer
Course: Network Security & Forensics (NSF)
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import io
import os

from config import THRESHOLDS, PORT_MAPPING, SEVERITY_LEVELS, INCIDENT_PLAYBOOK, THREAT_INTEL_BLACKLIST
from log_generator import NetworkLogGenerator, save_logs_to_file
from analyzer import LogAnalyzer
from report_generator import ForensicReportGenerator

# 1. Streamlit Page Configuration
st.set_page_config(
    page_title="SOC Network Log Analyzer & Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Custom CSS for Cybersecurity Dark SOC Theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@300;400;600;700&display=swap');

    /* Global styling */
    .stApp {
        background-color: #0B0F19;
        font-family: 'Inter', sans-serif;
        color: #E2E8F0;
    }

    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'JetBrains Mono', monospace !important;
        font-weight: 700 !important;
        letter-spacing: -0.5px;
    }

    /* Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8));
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 12px;
        padding: 18px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(8px);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: rgba(14, 165, 233, 0.4);
    }
    .metric-title {
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #94A3B8;
        font-weight: 600;
        margin-bottom: 6px;
    }
    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.85rem;
        font-weight: 800;
        color: #F8FAFC;
    }
    .metric-sub {
        font-size: 0.78rem;
        color: #64748B;
        margin-top: 4px;
    }

    /* Status Badges */
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #EF4444;
        border: 1px solid rgba(239, 68, 68, 0.4);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.2);
        color: #F97316;
        border: 1px solid rgba(249, 115, 22, 0.4);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-medium {
        background-color: rgba(234, 179, 8, 0.2);
        color: #EAB308;
        border: 1px solid rgba(234, 179, 8, 0.4);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-low {
        background-color: rgba(34, 197, 94, 0.2);
        color: #22C55E;
        border: 1px solid rgba(34, 197, 94, 0.4);
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }

    /* Cyber Glow Banner */
    .soc-header {
        background: linear-gradient(90deg, #0F172A 0%, #1E293B 50%, #0F172A 100%);
        border-left: 4px solid #0EA5E9;
        border-radius: 8px;
        padding: 16px 24px;
        margin-bottom: 24px;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
if "raw_logs_data" not in st.session_state:
    # Auto-generate initial sample dataset for immediate college demonstration
    gen = NetworkLogGenerator()
    st.session_state["raw_logs_data"] = gen.generate_dataset(normal_count=120, include_attacks=True)
    st.session_state["source_description"] = "Default Simulated SOC Traffic (Normal + 5 Attack Vectors)"


# ==========================================
# SIDEBAR CONTROLS & CONFIGURATION
# ==========================================
with st.sidebar:
    st.markdown("### 🛡️ SOC Defense Center")
    st.caption("Network Security & Forensics (NSF)")
    st.divider()

    st.markdown("#### 📂 1. Log Data Ingestion")
    data_source_mode = st.radio(
        "Select Log Ingestion Method:",
        ["⚡ Generate Attack Demo Logs", "📁 Upload External Log File", "💾 Load Pre-built Dataset"],
        index=0
    )

    if data_source_mode == "⚡ Generate Attack Demo Logs":
        st.markdown("**Attack Simulation Parameters:**")
        num_normal = st.slider("Normal Traffic Count", min_value=50, max_value=500, value=150, step=25)
        
        inc_brute = st.checkbox("SSH/Auth Brute Force", value=True)
        inc_scan = st.checkbox("Port Scanning Reconnaissance", value=True)
        inc_exfil = st.checkbox("Data Exfiltration Spikes", value=True)
        inc_web = st.checkbox("Web Exploits (SQLi, XSS, Path Traversal)", value=True)
        inc_dos = st.checkbox("Denial of Service (DoS Burst)", value=True)

        if st.button("🚀 Generate Attack Scenario", use_container_width=True, type="primary"):
            with st.spinner("Simulating network packets & attack vectors..."):
                gen = NetworkLogGenerator()
                logs = []
                for _ in range(num_normal):
                    logs.append(gen.generate_normal_log())
                if inc_brute:
                    logs.extend(gen.generate_brute_force_attack(attempts=14))
                if inc_scan:
                    logs.extend(gen.generate_port_scan_attack(num_ports=12))
                if inc_exfil:
                    logs.extend(gen.generate_data_exfiltration_attack())
                if inc_web:
                    logs.extend(gen.generate_web_attacks())
                if inc_dos:
                    logs.extend(gen.generate_dos_flood(count=45))

                logs.sort(key=lambda x: x["timestamp"])
                st.session_state["raw_logs_data"] = logs
                st.session_state["source_description"] = f"Generated Scenario ({len(logs)} logs with active attacks)"
                st.success(f"Generated {len(logs)} logs successfully!")
                st.rerun()

    elif data_source_mode == "📁 Upload External Log File":
        uploaded_file = st.file_uploader(
            "Upload Log File (.log, .txt, .csv)",
            type=["log", "txt", "csv"],
            help="Upload raw firewall, web server, or CSV security logs."
        )
        if uploaded_file is not None:
            if st.button("📥 Ingest & Analyze Uploaded Log", use_container_width=True, type="primary"):
                st.session_state["raw_logs_data"] = uploaded_file
                st.session_state["source_description"] = f"Uploaded File: {uploaded_file.name}"
                st.success(f"Loaded {uploaded_file.name}")
                st.rerun()

    elif data_source_mode == "💾 Load Pre-built Dataset":
        sample_choice = st.selectbox(
            "Select Pre-generated Dataset:",
            ["Mixed Cyber Attacks Dataset", "Normal Traffic Only (Baseline)"]
        )
        if st.button("Load Selected Dataset", use_container_width=True):
            gen = NetworkLogGenerator()
            include_atk = (sample_choice == "Mixed Cyber Attacks Dataset")
            st.session_state["raw_logs_data"] = gen.generate_dataset(normal_count=180, include_attacks=include_atk)
            st.session_state["source_description"] = sample_choice
            st.success("Loaded dataset!")
            st.rerun()

    st.divider()
    st.markdown("#### ⚙️ 2. Detection Sensitivity Thresholds")
    
    t_brute = st.slider("Brute Force Threshold (Fails)", min_value=2, max_value=15, value=THRESHOLDS["brute_force_attempts"])
    t_scan = st.slider("Port Scan Threshold (Ports)", min_value=3, max_value=20, value=THRESHOLDS["port_scan_unique_ports"])
    t_exfil_mb = st.slider("Data Exfil Limit (MB)", min_value=1, max_value=50, value=int(THRESHOLDS["high_bandwidth_bytes"] / (1024 * 1024)))
    t_dos = st.slider("DoS Request Burst Rate", min_value=10, max_value=100, value=THRESHOLDS["dos_request_threshold"])

    active_thresholds = {
        "brute_force_attempts": t_brute,
        "brute_force_window_seconds": 60,
        "port_scan_unique_ports": t_scan,
        "port_scan_window_seconds": 60,
        "high_bandwidth_bytes": t_exfil_mb * 1024 * 1024,
        "exfiltration_total_bytes": 20 * 1024 * 1024,
        "dos_request_threshold": t_dos,
        "dos_window_seconds": 30
    }

    st.divider()
    st.caption("College Mini Project: Network Security & Forensics")


# ==========================================
# CORE PROCESSING & ANALYSIS
# ==========================================
analyzer = LogAnalyzer(thresholds=active_thresholds)

if isinstance(st.session_state["raw_logs_data"], list):
    df_logs = pd.DataFrame(st.session_state["raw_logs_data"])
    analyzer.parse_logs(df_logs)
else:
    # Streamlit UploadedFile or string
    analyzer.parse_logs(st.session_state["raw_logs_data"])

analysis_results = analyzer.analyze()
metrics = analysis_results["metrics"]
alerts = analysis_results["alerts"]
alerts_df = analysis_results["alerts_df"]
df_analyzed = analysis_results["df"]


# ==========================================
# MAIN DASHBOARD HEADER & KPI METRICS
# ==========================================
st.markdown(f"""
<div class="soc-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h2 style="color: #0EA5E9; margin: 0; font-size: 1.5rem;">🛡️ Network Log Analyzer & Security Audit System</h2>
            <p style="color: #94A3B8; margin: 4px 0 0 0; font-size: 0.85rem;">
                Active Source: <b>{st.session_state.get('source_description', 'Simulated Stream')}</b> &nbsp;|&nbsp; 
                Forensics Engine: <b>Online & Active</b>
            </p>
        </div>
        <div style="text-align: right;">
            <span style="background: rgba(14, 165, 233, 0.15); border: 1px solid #0EA5E9; color: #38BDF8; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-family: monospace;">
                ● LIVE AUDITING
            </span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# 4 Key Metrics Cards
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">📊 Total Logs Analyzed</div>
        <div class="metric-value">{metrics.get('total_logs', 0):,}</div>
        <div class="metric-sub">{metrics.get('unique_source_ips', 0)} Unique Source Hosts</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    threat_cnt = metrics.get('total_threats', 0)
    threat_color = "#EF4444" if threat_cnt > 0 else "#22C55E"
    st.markdown(f"""
    <div class="metric-card" style="border-left: 3px solid {threat_color};">
        <div class="metric-title">⚠️ Threats Flagged</div>
        <div class="metric-value" style="color: {threat_color};">{threat_cnt}</div>
        <div class="metric-sub">{metrics.get('severity_counts', {}).get('CRITICAL', 0)} Critical, {metrics.get('severity_counts', {}).get('HIGH', 0)} High</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    risk_score = metrics.get('overall_risk_score', 0)
    risk_color = "#EF4444" if risk_score > 70 else ("#F97316" if risk_score > 40 else ("#EAB308" if risk_score > 15 else "#22C55E"))
    st.markdown(f"""
    <div class="metric-card" style="border-left: 3px solid {risk_color};">
        <div class="metric-title">🎯 Threat Risk Score</div>
        <div class="metric-value" style="color: {risk_color};">{risk_score} <span style="font-size: 1rem; color: #64748B;">/ 100</span></div>
        <div class="metric-sub">{'CRITICAL RISK' if risk_score > 70 else ('ELEVATED RISK' if risk_score > 30 else 'LOW / NORMAL')}</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">🌐 Network Payload Volume</div>
        <div class="metric-value">{metrics.get('total_megabytes', 0)} <span style="font-size: 1rem; color: #64748B;">MB</span></div>
        <div class="metric-sub">{metrics.get('unique_destination_ips', 0)} Monitored Internal Assets</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)


# ==========================================
# MULTI-TAB DASHBOARD NAVIGATION
# ==========================================
tab_overview, tab_investigation, tab_playbook, tab_report = st.tabs([
    "📈 SOC Threat Analytics",
    "🔍 Forensics Investigation Table",
    "🛡️ Incident Response Playbook",
    "📑 Executive Audit Report Export"
])


# ==========================================
# TAB 1: SOC THREAT ANALYTICS & VISUALIZATIONS
# ==========================================
with tab_overview:
    row1_c1, row1_c2 = st.columns([1, 1])

    with row1_c1:
        st.markdown("#### 🎯 Threat Severity Distribution")
        sev_counts = metrics.get("severity_counts", {})
        sev_df = pd.DataFrame([
            {"Severity": k, "Count": v, "Color": SEVERITY_LEVELS[k]["color"]}
            for k, v in sev_counts.items() if v > 0
        ])
        
        if not sev_df.empty:
            fig_sev = px.pie(
                sev_df,
                names="Severity",
                values="Count",
                hole=0.55,
                color="Severity",
                color_discrete_map={row["Severity"]: row["Color"] for _, row in sev_df.iterrows()}
            )
            fig_sev.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0", family="Inter"),
                margin=dict(t=20, b=20, l=20, r=20),
                legend=dict(orientation="h", y=-0.1, x=0.2)
            )
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No security threats detected in current logs.")

    with row1_c2:
        st.markdown("#### 🚨 Detected Cyber Attack Categories")
        atk_counts = metrics.get("attack_type_counts", {})
        if atk_counts:
            atk_df = pd.DataFrame(list(atk_counts.items()), columns=["Attack Category", "Incidents"])
            atk_df = atk_df.sort_values(by="Incidents", ascending=True)
            
            fig_atk = px.bar(
                atk_df,
                x="Incidents",
                y="Attack Category",
                orientation="h",
                text="Incidents",
                color="Incidents",
                color_continuous_scale="Reds"
            )
            fig_atk.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0", family="Inter"),
                xaxis=dict(showgrid=True, gridcolor="#1E293B"),
                yaxis=dict(showgrid=False),
                margin=dict(t=20, b=20, l=20, r=20),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_atk, use_container_width=True)
        else:
            st.info("No attacks categorized.")

    st.divider()

    row2_c1, row2_c2 = st.columns([1, 1])

    with row2_c1:
        st.markdown("#### 🏴‍☠️ Top Attacking Source IPs")
        top_atk = metrics.get("top_attackers", {})
        if top_atk:
            top_df = pd.DataFrame(list(top_atk.items()), columns=["Source IP", "Violations"]).sort_values(by="Violations", ascending=False).head(8)
            # Add threat intel annotation if known
            top_df["Reputation"] = top_df["Source IP"].apply(lambda ip: THREAT_INTEL_BLACKLIST.get(ip, {}).get("reputation", "Suspicious Host"))
            
            fig_top = px.bar(
                top_df,
                x="Source IP",
                y="Violations",
                color="Reputation",
                text="Violations"
            )
            fig_top.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0", family="Inter"),
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor="#1E293B"),
                margin=dict(t=20, b=20, l=20, r=20)
            )
            st.plotly_chart(fig_top, use_container_width=True)
        else:
            st.info("No attacking IPs recorded.")

    with row2_c2:
        st.markdown("#### 🎯 Targeted Ports & Services")
        if not df_analyzed.empty:
            port_counts = df_analyzed["service"].value_counts().head(8).reset_index()
            port_counts.columns = ["Service / Port", "Total Requests"]
            
            fig_port = px.pie(
                port_counts,
                names="Service / Port",
                values="Total Requests",
                hole=0.45,
                color_discrete_sequence=px.colors.sequential.Teal
            )
            fig_port.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0", family="Inter"),
                margin=dict(t=20, b=20, l=20, r=20),
                legend=dict(orientation="h", y=-0.1, x=0.1)
            )
            st.plotly_chart(fig_port, use_container_width=True)

    # Timeline of Attacks
    st.divider()
    st.markdown("#### ⏱️ Network Traffic & Security Events Timeline")
    if not df_analyzed.empty:
        time_df = df_analyzed.copy()
        time_df["time_bucket"] = pd.to_datetime(time_df["timestamp"]).dt.floor("1min")
        time_counts = time_df.groupby(["time_bucket", "action"]).size().reset_index(name="Packet Count")

        fig_time = px.line(
            time_counts,
            x="time_bucket",
            y="Packet Count",
            color="action",
            color_discrete_map={"ALLOW": "#0EA5E9", "BLOCK": "#EF4444", "DROP": "#F97316", "UNKNOWN": "#94A3B8"},
            markers=True
        )
        fig_time.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E2E8F0", family="Inter"),
            xaxis=dict(showgrid=True, gridcolor="#1E293B", title="Timeline (UTC)"),
            yaxis=dict(showgrid=True, gridcolor="#1E293B", title="Event Count"),
            margin=dict(t=20, b=20, l=20, r=20)
        )
        st.plotly_chart(fig_time, use_container_width=True)


# ==========================================
# TAB 2: FORENSIC INVESTIGATION TABLE & RAW LOGS
# ==========================================
with tab_investigation:
    st.markdown("### 🔎 Forensic Evidence Investigation")
    st.caption("Deep-dive into Indicators of Compromise (IOCs), raw attack payloads, and timestamped forensic logs.")

    if not alerts_df.empty:
        # Search & Filter Controls
        f_col1, f_col2, f_col3 = st.columns([1, 1, 1])
        with f_col1:
            sev_filter = st.multiselect("Filter by Severity:", options=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM"])
        with f_col2:
            unique_atks = alerts_df["attack_type"].unique().tolist()
            atk_filter = st.multiselect("Filter by Attack Category:", options=unique_atks, default=unique_atks)
        with f_col3:
            ip_search = st.text_input("🔍 Search Source / Target IP:", placeholder="e.g. 194.26 or 192.168")

        # Apply Filters
        filtered_alerts = alerts_df.copy()
        if sev_filter:
            filtered_alerts = filtered_alerts[filtered_alerts["severity"].isin(sev_filter)]
        if atk_filter:
            filtered_alerts = filtered_alerts[filtered_alerts["attack_type"].isin(atk_filter)]
        if ip_search:
            filtered_alerts = filtered_alerts[
                filtered_alerts["source_ip"].str.contains(ip_search, case=False, na=False) |
                filtered_alerts["destination_ip"].str.contains(ip_search, case=False, na=False)
            ]

        st.markdown(f"**Showing {len(filtered_alerts)} of {len(alerts_df)} detected security alerts:**")
        
        # Display formatted table
        display_df = filtered_alerts[["timestamp", "source_ip", "destination_ip", "destination_port", "service", "attack_type", "severity", "description"]].copy()
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.TextColumn("Timestamp"),
                "source_ip": st.column_config.TextColumn("Attacker Source IP"),
                "destination_ip": st.column_config.TextColumn("Target IP"),
                "destination_port": st.column_config.NumberColumn("Target Port"),
                "service": st.column_config.TextColumn("Target Service"),
                "attack_type": st.column_config.TextColumn("Attack Classification"),
                "severity": st.column_config.TextColumn("Severity Level"),
                "description": st.column_config.TextColumn("Forensic Description")
            }
        )

        # Expandable Detail View
        st.markdown("#### 🔬 Detailed Forensic Evidence Cards")
        for idx, row in filtered_alerts.iterrows():
            sev_badge = f'<span class="badge-{row["severity"].lower()}">{row["severity"]}</span>'
            with st.expander(f"Incident #{idx+1}: [{row['severity']}] {row['attack_type']} from {row['source_ip']} -> {row['destination_ip']}:{row['destination_port']}"):
                c1, c2 = st.columns([1, 1])
                with c1:
                    st.markdown(f"**Timestamp:** `{row['timestamp']}`")
                    st.markdown(f"**Attacker IP:** `{row['source_ip']}`")
                    st.markdown(f"**Target Asset:** `{row['destination_ip']}:{row['destination_port']} ({row['service']})`")
                    st.markdown(f"**Severity:** {sev_badge}", unsafe_allow_html=True)
                with c2:
                    st.markdown(f"**Attack Type:** `{row['attack_type']}`")
                    st.markdown(f"**Description:** {row['description']}")
                
                st.markdown(f"**📌 Forensic Evidence / Signature:**")
                st.code(row['evidence'], language="text")

                st.markdown(f"**🛠️ Recommended Immediate Action:**")
                st.info(row['recommendation'])

    else:
        st.success("No threat alerts detected in the loaded dataset.")

    st.divider()
    st.markdown("### 📜 Raw Ingested Log Viewer")
    with st.expander("Click to view all raw network log entries"):
        if not df_analyzed.empty:
            st.dataframe(
                df_analyzed[["timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "action", "status_code", "bytes_transferred", "message"]],
                use_container_width=True,
                hide_index=True
            )


# ==========================================
# TAB 3: INCIDENT RESPONSE PLAYBOOK
# ==========================================
with tab_playbook:
    st.markdown("### 🛡️ SOC Incident Response & Mitigation Playbook")
    st.caption("Standard Operating Procedures (SOPs) based on NIST SP 800-61 Computer Security Incident Handling Guide.")

    detected_types = list(metrics.get("attack_type_counts", {}).keys())

    for attack_name, steps in INCIDENT_PLAYBOOK.items():
        is_active = any(attack_name.split()[0].lower() in dt.lower() for dt in detected_types)
        status_text = "🚨 ACTIVE THREAT IN LOGS" if is_active else "🟢 STANDBY"
        status_color = "#EF4444" if is_active else "#64748B"

        with st.expander(f"Playbook: {attack_name}  [{status_text}]"):
            st.markdown(f"**Threat Status:** <span style='color:{status_color}; font-weight:bold;'>{status_text}</span>", unsafe_allow_html=True)
            st.markdown("#### Recommended Containment & Remediation Workflow:")
            for i, step in enumerate(steps, 1):
                st.markdown(f"**Step {i}:** {step}")
            
            st.markdown("---")
            st.markdown("**Sample Firewall / CLI Mitigation Command:**")
            if "Brute Force" in attack_name or "Blacklisted" in attack_name:
                st.code(f"sudo iptables -A INPUT -s 194.26.29.112 -j DROP\nsudo fail2ban-client set sshd banip 194.26.29.112", language="bash")
            elif "Port Scan" in attack_name:
                st.code("sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP\nsudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP", language="bash")
            elif "Data Exfiltration" in attack_name:
                st.code("sudo ip route add blackhole 103.203.57.18\nsudo iptables -A FORWARD -s 192.168.1.25 -j DROP", language="bash")
            else:
                st.code("sudo ufw deny from 185.220.101.5 to any port 80,443 proto tcp", language="bash")


# ==========================================
# TAB 4: FORENSIC REPORT GENERATOR & EXPORT
# ==========================================
with tab_report:
    st.markdown("### 📑 Security Audit & Forensics Report Generator")
    st.caption("Generate official PDF and CSV forensic reports for compliance, viva submission, and SIEM integration.")

    rep_col1, rep_col2 = st.columns([1, 1])

    with rep_col1:
        st.markdown("#### 📄 Executive Security Audit PDF Report")
        st.markdown(
            "Includes formal Executive Summary, Risk Score Matrix, Severity Breakdown, "
            "Table of Indicators of Compromise (IOCs), and Remediation Action Plan."
        )
        
        # Generate PDF in memory
        rep_gen = ForensicReportGenerator(analysis_results, audit_title="Network Security & Forensic Audit Report")
        pdf_bytes = rep_gen.generate_pdf_report()

        st.download_button(
            label="⬇️ Download Official PDF Audit Report",
            data=pdf_bytes,
            file_name=f"Security_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
            use_container_width=True,
            type="primary"
        )

    with rep_col2:
        st.markdown("#### 📊 Forensics Alerts CSV Export")
        st.markdown(
            "Export all detected security anomalies, timestamps, IP addresses, evidence snippets, "
            "and severity classifications for ingestion into SIEM tools (e.g. Splunk, Elastic, Sentinel)."
        )

        csv_data = rep_gen.export_csv()
        st.download_button(
            label="⬇️ Download SIEM Alerts CSV",
            data=csv_data,
            file_name=f"Forensic_Alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.divider()

    # Raw Log Download
    st.markdown("#### 💾 Raw Log Archive Export")
    if isinstance(st.session_state["raw_logs_data"], list):
        raw_log_text = "\n".join([item.get("raw_log", "") for item in st.session_state["raw_logs_data"]])
    else:
        raw_log_text = str(st.session_state["raw_logs_data"])

    st.download_button(
        label="⬇️ Download Raw Ingested Logs (.log)",
        data=raw_log_text,
        file_name=f"raw_network_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
        mime="text/plain"
    )
