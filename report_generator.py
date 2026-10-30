"""
Network Log Analyzer - Forensic Security Audit Report Generator
Author: Senior Cybersecurity Engineer
Course: Network Security & Forensics (NSF)
"""

import os
import io
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)


class ForensicReportGenerator:
    """Generates PDF and CSV Security Audit & Forensic Investigation Reports."""

    def __init__(self, analysis_results, audit_title="Network Security & Forensic Audit Report"):
        self.results = analysis_results
        self.metrics = analysis_results.get("metrics", {})
        self.alerts = analysis_results.get("alerts", [])
        self.audit_title = audit_title

    def export_csv(self, output_path=None):
        """Exports detected threat alerts to a structured CSV format."""
        if not self.alerts:
            df = pd.DataFrame(columns=["timestamp", "source_ip", "destination_ip", "destination_port", "service", "attack_type", "severity", "description", "evidence", "recommendation"])
        else:
            df = pd.DataFrame(self.alerts)

        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            df.to_csv(output_path, index=False)
            return output_path
        else:
            csv_buffer = io.StringIO()
            df.to_csv(csv_buffer, index=False)
            return csv_buffer.getvalue()

    def generate_pdf_report(self, output_path=None):
        """Generates a professional PDF Security Audit Report."""
        buffer = io.BytesIO() if output_path is None else open(output_path, "wb")
        
        doc = SimpleDocTemplate(
            output_path if output_path else buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography & Styling
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569'),
            spaceAfter=15
        )
        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=12,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#334155')
        )
        bold_body = ParagraphStyle(
            'BoldBody',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        elements = []

        # 1. Header Banner
        elements.append(Paragraph(self.audit_title, title_style))
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"<b>Generated:</b> {gen_time} &nbsp;|&nbsp; <b>Classification:</b> CONFIDENTIAL / FORENSIC AUDIT", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0EA5E9'), spaceAfter=15))

        # 2. Executive Summary Box
        risk_score = self.metrics.get('overall_risk_score', 0)
        risk_label = "CRITICAL" if risk_score > 70 else ("HIGH" if risk_score > 40 else ("MEDIUM" if risk_score > 15 else "LOW"))
        risk_color = "#DC2626" if risk_score > 70 else ("#EA580C" if risk_score > 40 else ("#D97706" if risk_score > 15 else "#16A34A"))

        summary_text = (
            f"During the automated forensic security log audit, a total of <b>{self.metrics.get('total_logs', 0):,}</b> network access "
            f"and firewall transaction records were analyzed. A total of <b>{self.metrics.get('total_threats', 0)}</b> security threats and policy "
            f"violations were flagged across <b>{self.metrics.get('unique_source_ips', 0)}</b> unique source hosts.<br/><br/>"
            f"Overall System Risk Posture is evaluated at: <b><font color='{risk_color}'>{risk_score}/100 ({risk_label} RISK)</font></b>."
        )
        
        summary_table = Table([[Paragraph(summary_text, body_style)]], colWidths=[540])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # 3. Security Metrics & Severity Distribution
        elements.append(Paragraph("1. Audit Summary & Severity Metrics", h2_style))
        sev = self.metrics.get("severity_counts", {})
        
        metrics_data = [
            [
                Paragraph("<b>Total Logs Analyzed</b>", bold_body),
                Paragraph(f"{self.metrics.get('total_logs', 0):,}", body_style),
                Paragraph("<b>Critical Severity Alerts</b>", bold_body),
                Paragraph(f"<font color='#DC2626'><b>{sev.get('CRITICAL', 0)}</b></font>", body_style)
            ],
            [
                Paragraph("<b>Total Threats Flagged</b>", bold_body),
                Paragraph(f"{self.metrics.get('total_threats', 0)}", body_style),
                Paragraph("<b>High Severity Alerts</b>", bold_body),
                Paragraph(f"<font color='#EA580C'><b>{sev.get('HIGH', 0)}</b></font>", body_style)
            ],
            [
                Paragraph("<b>Total Data Volume</b>", bold_body),
                Paragraph(f"{self.metrics.get('total_megabytes', 0)} MB", body_style),
                Paragraph("<b>Medium Severity Alerts</b>", bold_body),
                Paragraph(f"<font color='#D97706'><b>{sev.get('MEDIUM', 0)}</b></font>", body_style)
            ],
            [
                Paragraph("<b>Monitored Subnets</b>", bold_body),
                Paragraph(f"{self.metrics.get('unique_destination_ips', 0)} Internal/Target IPs", body_style),
                Paragraph("<b>Low / Info Alerts</b>", bold_body),
                Paragraph(f"<font color='#16A34A'><b>{sev.get('LOW', 0)}</b></font>", body_style)
            ]
        ]
        
        m_table = Table(metrics_data, colWidths=[140, 130, 140, 130])
        m_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FFFFFF')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(m_table)
        elements.append(Spacer(1, 15))

        # 4. Indicators of Compromise (IOCs) & Detected Attack Log
        elements.append(Paragraph("2. Detected Threat Incidents & Forensic Evidence", h2_style))
        
        if not self.alerts:
            elements.append(Paragraph("<i>No suspicious security anomalies or cyber attacks detected in the analyzed logs.</i>", body_style))
        else:
            threat_headers = ["Timestamp", "Source IP", "Target Asset", "Attack Vector", "Severity"]
            threat_rows = [[Paragraph(f"<b>{h}</b>", bold_body) for h in threat_headers]]
            
            # Display up to 15 top alerts to fit cleanly in report
            for alert in self.alerts[:15]:
                sev_str = alert['severity']
                sev_color = "#DC2626" if sev_str == "CRITICAL" else ("#EA580C" if sev_str == "HIGH" else "#D97706")
                
                target_str = f"{alert['destination_ip']}:{alert['destination_port']}" if alert['destination_port'] > 0 else alert['destination_ip']
                threat_rows.append([
                    Paragraph(str(alert['timestamp'])[-8:], body_style),
                    Paragraph(str(alert['source_ip']), body_style),
                    Paragraph(target_str, body_style),
                    Paragraph(str(alert['attack_type']), body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{sev_str}</b></font>", body_style)
                ])

            t_table = Table(threat_rows, colWidths=[65, 95, 110, 200, 70])
            t_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(t_table)

        elements.append(Spacer(1, 15))

        # 5. Incident Remediation Playbook
        elements.append(Paragraph("3. Recommended Incident Remediation Actions", h2_style))
        remediation_items = [
            "<b>Host Isolation:</b> Immediately quarantine internal hosts involved in high-bandwidth exfiltration (e.g. 192.168.1.25).",
            "<b>Firewall Rule Updates:</b> Blacklist detected reconnaissance and brute-force source IPs (e.g. 45.155.205.233, 194.26.29.112).",
            "<b>WAF Signature Tuning:</b> Enforce strict input validation and SQLi/XSS filtering on public web entrypoints.",
            "<b>Credential Rotation:</b> Force password resets and mandate MFA for all administrator accounts on port 22/3389."
        ]
        for r in remediation_items:
            elements.append(Paragraph(f"• {r}", body_style))
            elements.append(Spacer(1, 3))

        # Build document
        doc.build(elements)

        if output_path:
            return output_path
        else:
            buffer.seek(0)
            return buffer.getvalue()


if __name__ == "__main__":
    from analyzer import LogAnalyzer
    from log_generator import NetworkLogGenerator
    
    print("[*] Generating test dataset and PDF audit report...")
    gen = NetworkLogGenerator()
    data = gen.generate_dataset(normal_count=100, include_attacks=True)
    analyzer = LogAnalyzer()
    analyzer.parse_logs(pd.DataFrame(data))
    results = analyzer.analyze()
    
    rep_gen = ForensicReportGenerator(results)
    out_file = rep_gen.generate_pdf_report("sample_logs/security_audit_report.pdf")
    print(f"[+] Security Audit PDF created successfully at: {out_file}")
