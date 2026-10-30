import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

def create_dashboard_img():
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=150)
    fig.patch.set_facecolor('#0B0F19')
    ax.set_facecolor('#0B0F19')
    
    ax.text(0.5, 0.93, 'SOC Network Log Analyzer - Real-Time Forensic Dashboard', color='#38BDF8', fontsize=13, weight='bold', ha='center')
    
    kpis = [('TOTAL LOGS', '2,450', '#38BDF8'), ('THREATS DETECTED', '48', '#EF4444'), ('NETWORK RISK SCORE', '82 / 100', '#F59E0B'), ('DATA VOLUME', '142.8 MB', '#10B981')]
    for i, (title, val, col) in enumerate(kpis):
        x = 0.05 + i * 0.235
        rect = patches.FancyBboxPatch((x, 0.72), 0.21, 0.16, boxstyle='round,pad=0.02', facecolor='#1E293B', edgecolor='#334155', linewidth=1)
        ax.add_patch(rect)
        ax.text(x + 0.105, 0.83, title, color='#94A3B8', fontsize=7.5, weight='bold', ha='center')
        ax.text(x + 0.105, 0.75, val, color=col, fontsize=12, weight='bold', ha='center')
        
    rect2 = patches.FancyBboxPatch((0.05, 0.18), 0.44, 0.50, boxstyle='round,pad=0.02', facecolor='#1E293B', edgecolor='#334155', linewidth=1)
    ax.add_patch(rect2)
    ax.text(0.27, 0.63, 'Threat Distribution by Attack Vector', color='#E2E8F0', fontsize=9, weight='bold', ha='center')
    attacks = ['Brute Force', 'Port Scan', 'Exfiltration', 'SQLi / XSS', 'DoS Flood']
    counts = [12, 10, 8, 14, 4]
    colors = ['#F97316', '#EAB308', '#EF4444', '#EC4899', '#8B5CF6']
    y_pos = [0.55, 0.47, 0.39, 0.31, 0.23]
    for atk, cnt, col, y in zip(attacks, counts, colors, y_pos):
        ax.text(0.08, y, atk, color='#CBD5E1', fontsize=7.5, va='center')
        bar = patches.Rectangle((0.21, y - 0.02), cnt * 0.015, 0.04, facecolor=col)
        ax.add_patch(bar)
        ax.text(0.22 + cnt * 0.015, y, str(cnt), color=col, fontsize=7.5, va='center', weight='bold')

    rect3 = patches.FancyBboxPatch((0.52, 0.18), 0.43, 0.50, boxstyle='round,pad=0.02', facecolor='#1E293B', edgecolor='#334155', linewidth=1)
    ax.add_patch(rect3)
    ax.text(0.735, 0.63, 'Live Network Event Flurry Timeline', color='#E2E8F0', fontsize=9, weight='bold', ha='center')
    x_line = np.linspace(0.55, 0.92, 20)
    y_line = 0.35 + 0.10 * np.sin(np.linspace(0, 3*np.pi, 20))
    ax.plot(x_line, y_line, color='#38BDF8', linewidth=2)
    ax.axhline(0.48, color='#EF4444', linestyle='--', linewidth=1, xmin=0.55, xmax=0.92)
    ax.text(0.735, 0.50, 'Anomaly Burst Threshold', color='#EF4444', fontsize=7, ha='center')

    ax.text(0.5, 0.08, 'Streamlit SOC Dashboard - B.Tech CSCF Mini Project | Srinivas University', color='#64748B', fontsize=8, ha='center')

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    plt.tight_layout()
    plt.savefig('dashboard.png', facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()

def create_threat_detection_img():
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=150)
    fig.patch.set_facecolor('#0B0F19')
    ax.set_facecolor('#0B0F19')
    
    ax.text(0.5, 0.93, 'Real-Time Threat Detection & Heuristic Alerts Registry', color='#EF4444', fontsize=13, weight='bold', ha='center')
    
    headers = ['TIMESTAMP', 'SOURCE IP', 'TARGET IP:PORT', 'ATTACK VECTOR', 'SEVERITY', 'FORENSIC EVIDENCE']
    x_cols = [0.04, 0.19, 0.34, 0.52, 0.69, 0.81]
    for h, x in zip(headers, x_cols):
        ax.text(x, 0.83, h, color='#94A3B8', fontsize=8, weight='bold')
    
    alerts = [
        ('18:30:15', '192.168.1.105', '10.0.0.5:22', 'SSH Brute Force', 'HIGH', '6 failed logins in 45s (Thresh: 4)'),
        ('18:31:02', '45.155.205.233', '10.0.0.12:80', 'Threat Intel Recon', 'CRITICAL', 'ShadowServer Scanner match'),
        ('18:31:44', '192.168.1.15', '10.0.0.5:0', 'Port Scanning', 'HIGH', 'Probed 28 distinct ports in 40s'),
        ('18:32:10', '10.0.0.108', '10.0.0.5:80', 'SQL Injection (SQLi)', 'CRITICAL', 'Matched payload in URI login.php'),
        ('18:33:05', '172.16.0.44', '198.51.100.42:443', 'Data Exfiltration', 'CRITICAL', 'Outbound Spike: 24.6 MB transferred'),
        ('18:33:50', '192.168.1.200', '10.0.0.5:8080', 'DoS Request Flood', 'CRITICAL', '64 req/30s targeting Tomcat')
    ]
    
    sev_colors = {'CRITICAL': '#EF4444', 'HIGH': '#F97316', 'MEDIUM': '#F59E0B'}
    
    y = 0.74
    for t, src, dst, atk, sev, ev in alerts:
        box = patches.FancyBboxPatch((0.03, y - 0.035), 0.94, 0.08, boxstyle='round,pad=0.015', facecolor='#1E293B', edgecolor='#334155', linewidth=0.8)
        ax.add_patch(box)
        ax.text(0.04, y, t, color='#CBD5E1', fontsize=8)
        ax.text(0.19, y, src, color='#38BDF8', fontsize=8, weight='bold')
        ax.text(0.34, y, dst, color='#CBD5E1', fontsize=8)
        ax.text(0.52, y, atk, color='#F8FAFC', fontsize=8, weight='bold')
        
        s_box = patches.FancyBboxPatch((0.68, y - 0.025), 0.10, 0.05, boxstyle='round,pad=0.01', facecolor=sev_colors.get(sev, '#64748B'), edgecolor='none')
        ax.add_patch(s_box)
        ax.text(0.73, y, sev, color='white', fontsize=7, weight='bold', ha='center', va='center')
        
        ax.text(0.81, y, ev[:34], color='#94A3B8', fontsize=7)
        y -= 0.10
        
    ax.text(0.5, 0.08, 'Forensics Engine: Sliding-Window Heuristics + Threat Intel Blacklist Correlator', color='#64748B', fontsize=8, ha='center')
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    plt.tight_layout()
    plt.savefig('threat_detection.png', facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()

def create_audit_report_img():
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=150)
    fig.patch.set_facecolor('#0B0F19')
    ax.set_facecolor('#0B0F19')
    
    ax.text(0.5, 0.93, 'Forensic Audit Documentation & Export Engine (PDF / CSV)', color='#10B981', fontsize=13, weight='bold', ha='center')
    
    box_pdf = patches.FancyBboxPatch((0.05, 0.18), 0.42, 0.68, boxstyle='round,pad=0.02', facecolor='#F8FAFC', edgecolor='#334155', linewidth=1)
    ax.add_patch(box_pdf)
    
    header_band = patches.Rectangle((0.05, 0.77), 0.42, 0.09, facecolor='#1E3A8A')
    ax.add_patch(header_band)
    ax.text(0.26, 0.81, 'EXECUTIVE SECURITY AUDIT REPORT', color='white', fontsize=8, weight='bold', ha='center')
    ax.text(0.26, 0.73, 'NIST SP 800-61 Rev. 2 Aligned Evidence Summary', color='#475569', fontsize=6.5, ha='center')
    
    ax.text(0.08, 0.67, 'AUDIT METRICS:', color='#0F172A', fontsize=7, weight='bold')
    ax.text(0.08, 0.62, 'Total Records: 2,450   |   High-Risk IOCs: 6', color='#334155', fontsize=6)
    ax.text(0.08, 0.57, 'Overall Network Risk Level: CRITICAL (82/100)', color='#DC2626', fontsize=6.5, weight='bold')
    
    ax.text(0.08, 0.50, 'VERIFIED FORENSIC FINDINGS:', color='#0F172A', fontsize=7, weight='bold')
    findings = [
        '1. Tor Exit Node (185.220.101.5) access to Internal DB',
        '2. Horizontal Port Reconnaissance targeting 28 ports',
        '3. Critical Data Exfiltration anomaly spike of 24.6 MB'
    ]
    for i, f_text in enumerate(findings):
        ax.text(0.08, 0.45 - i * 0.045, f_text, color='#475569', fontsize=5.8)
        
    ax.text(0.08, 0.28, 'REMEDIATION PLAYBOOK ACTIONS:', color='#C2410C', fontsize=7, weight='bold')
    ax.text(0.08, 0.23, '1. Isolate compromised host IP 192.168.1.105 immediately.', color='#334155', fontsize=5.8)
    ax.text(0.08, 0.19, '2. Enforce lockout after 3 failed authentication bursts.', color='#334155', fontsize=5.8)

    box_csv = patches.FancyBboxPatch((0.53, 0.18), 0.42, 0.68, boxstyle='round,pad=0.02', facecolor='#1E293B', edgecolor='#334155', linewidth=1)
    ax.add_patch(box_csv)
    ax.text(0.74, 0.81, 'SIEM-Ready CSV Export Preview', color='#38BDF8', fontsize=9, weight='bold', ha='center')
    
    csv_rows = [
        'timestamp,source_ip,target_ip,attack,severity',
        '2026-09-10 18:30:15,192.168.1.105,10.0.0.5,BruteForce,HIGH',
        '2026-09-10 18:31:02,45.155.205.233,10.0.0.12,ThreatIntel,CRITICAL',
        '2026-09-10 18:31:44,192.168.1.15,10.0.0.5,PortScan,HIGH',
        '2026-09-10 18:32:10,10.0.0.108,10.0.0.5,SQLi,CRITICAL',
        '2026-09-10 18:33:05,172.16.0.44,198.51.100.42,DataExfil,CRITICAL',
        '2026-09-10 18:33:50,192.168.1.200,10.0.0.5,DoSFlood,CRITICAL'
    ]
    for i, r_text in enumerate(csv_rows):
        col = '#38BDF8' if i == 0 else '#94A3B8'
        wt = 'bold' if i == 0 else 'normal'
        ax.text(0.55, 0.72 - i * 0.065, r_text, color=col, fontsize=6.2, family='monospace', weight=wt)

    ax.text(0.5, 0.08, 'One-Click Compliance Reporting (ReportLab PDF Engine & Structured SIEM CSV)', color='#64748B', fontsize=8, ha='center')
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    plt.tight_layout()
    plt.savefig('audit_report.png', facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()

if __name__ == '__main__':
    create_dashboard_img()
    create_threat_detection_img()
    create_audit_report_img()
    print('Generated dashboard.png, threat_detection.png, audit_report.png')
