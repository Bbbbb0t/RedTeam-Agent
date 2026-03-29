# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
PDF Report Generator for RedTeam-Agent
Generates professional security assessment reports
Author: Abdulwahab Hamoud Salah
"""

import os
from datetime import datetime
from typing import Dict, List

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
except ImportError:
    print("[ERROR] reportlab not installed. Run: pip install reportlab")

# Tool metadata
TOOL_AUTHOR = "Abdulwahab Hamoud Salah"
TOOL_NAME = "RedTeam-Agent"


def generate_pdf(target: str, osint_data: Dict, scan_data: Dict, 
                 cve_data: List, ai_analysis: Dict) -> str:
    """
    Generate comprehensive PDF report
    
    English: Creates professional PDF report with all findings
    Arabic: إنشاء تقرير PDF احترافي مع جميع النتائج
    
    Args:
        target: Target domain/IP
        osint_data: OSINT reconnaissance results
        scan_data: Port scan and security results
        cve_data: CVE vulnerability findings
        ai_analysis: Analysis results
    
    Returns:
        Path to generated PDF file
    """
    try:
        # Create reports directory
        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('.', '_').replace('/', '_')
        filename = f"report_{safe_target}_{timestamp}.pdf"
        filepath = os.path.join('reports', filename)
        
        # Create PDF document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        # Container for story
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#16213e'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#0f3460'),
            spaceAfter=6,
            spaceBefore=6
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            alignment=TA_JUSTIFY,
            leading=14
        )
        
        footer_text = f"Security Report | Author: {TOOL_AUTHOR}"
        
        # === COVER PAGE ===
        story.append(Spacer(1, 1*inch))
        
        # Title
        story.append(Paragraph("SECURITY ASSESSMENT REPORT", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Target
        story.append(Paragraph(f"Target: {target}", heading_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Date
        report_date = datetime.now().strftime("%B %d, %Y")
        story.append(Paragraph(f"Date: {report_date}", subheading_style))
        story.append(Spacer(1, 0.5*inch))
        
        # Risk Score Badge
        risk_score = ai_analysis.get('risk_score', 5)
        if risk_score >= 8:
            risk_color = colors.red
            risk_label = "CRITICAL"
        elif risk_score >= 6:
            risk_color = colors.orange
            risk_label = "HIGH"
        elif risk_score >= 4:
            risk_color = colors.yellow
            risk_label = "MEDIUM"
        else:
            risk_color = colors.green
            risk_label = "LOW"
        
        risk_table = Table([[f"RISK SCORE: {risk_score}/10 ({risk_label})"]], colWidths=[4*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 18),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.8*inch))
        
        # Author credit - LARGE TEXT as required
        author_style = ParagraphStyle(
            'AuthorCredit',
            parent=styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#1a1a2e'),
            alignment=TA_CENTER,
            spaceBefore=20
        )
        story.append(Paragraph(f"<b>Tool Developed by: {TOOL_AUTHOR}</b>", author_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Tool info
        tool_info = f"{TOOL_NAME} v1.0"
        story.append(Paragraph(tool_info, subheading_style))
        story.append(Spacer(1, 1*inch))
        
        # Add page break
        story.append(PageBreak())
        
        # === TABLE OF CONTENTS ===
        story.append(Paragraph("TABLE OF CONTENTS", heading_style))
        toc_items = [
            "1. Executive Summary",
            "2. OSINT Findings",
            "3. Port Scan Results",
            "4. CVE Findings",
            "5. Risk Analysis & Recommendations",
            "6. Disclaimer"
        ]
        for item in toc_items:
            story.append(Paragraph(item, body_style))
            story.append(Spacer(1, 6))
        story.append(PageBreak())
        
        # === SECTION 1: EXECUTIVE SUMMARY ===
        story.append(Paragraph("1. EXECUTIVE SUMMARY", heading_style))
        
        exec_summary = ai_analysis.get('executive_summary', 'No executive summary available.')
        story.append(Paragraph(exec_summary, body_style))
        story.append(Spacer(1, 12))
        
        attack_surface = ai_analysis.get('attack_surface_summary', '')
        if attack_surface:
            story.append(Paragraph("<b>Attack Surface Overview:</b>", subheading_style))
            story.append(Paragraph(attack_surface, body_style))
        story.append(Spacer(1, 12))
        story.append(PageBreak())
        
        # === SECTION 2: OSINT FINDINGS ===
        story.append(Paragraph("2. OSINT FINDINGS", heading_style))
        
        # Subdomains
        story.append(Paragraph("<b>2.1 Discovered Subdomains</b>", subheading_style))
        subdomains = osint_data.get('subdomains', [])
        if subdomains:
            subdomain_data = [[sd] for sd in subdomains[:20]]  # Limit to 20
            subdomain_table = Table(subdomain_data, colWidths=[5*inch])
            subdomain_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(subdomain_table)
            if len(subdomains) > 20:
                story.append(Paragraph(f"... and {len(subdomains) - 20} more subdomains", body_style))
        else:
            story.append(Paragraph("No subdomains discovered.", body_style))
        story.append(Spacer(1, 12))
        
        # Emails
        story.append(Paragraph("<b>2.2 Discovered Email Addresses</b>", subheading_style))
        emails = osint_data.get('emails', [])
        if emails:
            email_data = [[email] for email in emails[:10]]
            email_table = Table(email_data, colWidths=[5*inch])
            email_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(email_table)
        else:
            story.append(Paragraph("No email addresses discovered.", body_style))
        story.append(Spacer(1, 12))
        
        # Technologies
        story.append(Paragraph("<b>2.3 Detected Technologies</b>", subheading_style))
        tech = osint_data.get('technologies', {})
        tech_info = []
        if tech.get('cms'):
            tech_info.append(f"CMS: {tech['cms']}")
        if tech.get('web_server'):
            tech_info.append(f"Web Server: {', '.join(tech['web_server'])}")
        if tech.get('frameworks'):
            tech_info.append(f"Frameworks: {', '.join(tech['frameworks'])}")
        if tech.get('programming_languages'):
            tech_info.append(f"Languages: {', '.join(tech['programming_languages'])}")
        
        if tech_info:
            for info in tech_info:
                story.append(Paragraph(f"• {info}", body_style))
        else:
            story.append(Paragraph("No specific technologies detected.", body_style))
        story.append(Spacer(1, 12))
        
        # IP Info
        story.append(Paragraph("<b>2.4 Server Location</b>", subheading_style))
        ip_info = osint_data.get('ip_info', {})
        if ip_info.get('ip'):
            story.append(Paragraph(f"IP Address: {ip_info.get('ip', 'N/A')}", body_style))
            story.append(Paragraph(f"Country: {ip_info.get('country', 'N/A')}", body_style))
            story.append(Paragraph(f"ISP: {ip_info.get('isp', 'N/A')}", body_style))
        story.append(Spacer(1, 12))
        story.append(PageBreak())
        
        # === SECTION 3: PORT SCAN RESULTS ===
        story.append(Paragraph("3. PORT SCAN RESULTS", heading_style))
        
        ports = scan_data.get('ports', {})
        if ports:
            port_data = [['Port', 'Service', 'Version', 'State']]
            for port, info in sorted(ports.items()):
                port_data.append([
                    str(port),
                    info.get('service', 'unknown'),
                    info.get('version', '')[:20] or info.get('product', '')[:20],
                    info.get('state', 'unknown')
                ])
            
            port_table = Table(port_data, colWidths=[1*inch, 1.5*inch, 2*inch, 1*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            story.append(port_table)
        else:
            story.append(Paragraph("No open ports detected or scan not performed.", body_style))
        story.append(Spacer(1, 12))
        
        # Security Headers
        story.append(Paragraph("<b>3.1 Security Headers Analysis</b>", subheading_style))
        headers = scan_data.get('security_headers', {})
        score = headers.get('score', 0)
        total = headers.get('total', 7)
        story.append(Paragraph(f"Security Headers Score: {score}/{total}", body_style))
        story.append(Spacer(1, 6))
        
        header_names = {
            'strict_transport_security': 'Strict-Transport-Security (HSTS)',
            'content_security_policy': 'Content-Security-Policy',
            'x_frame_options': 'X-Frame-Options',
            'x_content_type_options': 'X-Content-Type-Options',
            'x_xss_protection': 'X-XSS-Protection',
            'referrer_policy': 'Referrer-Policy',
            'permissions_policy': 'Permissions-Policy'
        }
        
        header_table_data = [['Header', 'Status']]
        for key, name in header_names.items():
            status = headers.get(key, {}).get('status', 'MISSING')
            header_table_data.append([name, status])
        
        header_table = Table(header_table_data, colWidths=[3.5*inch, 1.5*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 12))
        
        # SSL Info
        ssl_info = scan_data.get('ssl', {})
        if ssl_info:
            story.append(Paragraph("<b>3.2 SSL Certificate Information</b>", subheading_style))
            if ssl_info.get('valid'):
                story.append(Paragraph(f"✓ Valid certificate from: {ssl_info.get('issuer', 'Unknown')}", body_style))
                days = ssl_info.get('days_until_expiry', 0)
                story.append(Paragraph(f"Expires in: {days} days", body_style))
                if ssl_info.get('expires_soon'):
                    story.append(Paragraph("⚠ WARNING: Certificate expires soon!", body_style))
            else:
                error = ssl_info.get('error', 'Certificate information unavailable')
                story.append(Paragraph(f"Certificate Status: {error}", body_style))
        story.append(Spacer(1, 12))
        story.append(PageBreak())
        
        # === SECTION 4: CVE FINDINGS ===
        story.append(Paragraph("4. CVE FINDINGS", heading_style))
        
        if cve_data:
            cve_table_data = [['CVE ID', 'Severity', 'Score', 'Description']]
            for cve in cve_data[:15]:  # Limit to 15
                severity = cve.get('severity', 'UNKNOWN')
                sev_color = colors.black
                if severity == 'CRITICAL':
                    sev_color = colors.darkred
                elif severity == 'HIGH':
                    sev_color = colors.red
                elif severity == 'MEDIUM':
                    sev_color = colors.orange
                
                cve_table_data.append([
                    cve.get('cve_id', 'Unknown'),
                    Paragraph(f"<font color='{sev_color.hexval()}'><b>{severity}</b></font>", body_style),
                    str(cve.get('score', 'N/A')),
                    cve.get('description', '')[:80] + '...'
                ])
            
            cve_table = Table(cve_table_data, colWidths=[1.2*inch, 0.8*inch, 0.6*inch, 3*inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(cve_table)
            
            if len(cve_data) > 15:
                story.append(Paragraph(f"... and {len(cve_data) - 15} more CVEs", body_style))
        else:
            story.append(Paragraph("No CVEs found for the identified services.", body_style))
        story.append(Spacer(1, 12))
        story.append(PageBreak())
        
        # === SECTION 5: AI RISK ANALYSIS ===
        story.append(Paragraph("5. RISK ANALYSIS & RECOMMENDATIONS", heading_style))
        
        # Top Risks
        story.append(Paragraph("<b>5.1 Top Critical Risks</b>", subheading_style))
        top_risks = ai_analysis.get('top_risks', [])
        if top_risks:
            for i, risk in enumerate(top_risks, 1):
                story.append(Paragraph(f"{i}. {risk}", body_style))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("No critical risks identified.", body_style))
        story.append(Spacer(1, 12))
        
        # Remediation Steps
        story.append(Paragraph("<b>5.2 Recommended Remediation Steps</b>", subheading_style))
        remediation = ai_analysis.get('remediation_steps', [])
        if remediation:
            for i, step in enumerate(remediation, 1):
                story.append(Paragraph(f"{i}. {step}", body_style))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("No specific remediation steps available.", body_style))
        story.append(Spacer(1, 12))
        story.append(PageBreak())
        
        # === SECTION 6: DISCLAIMER ===
        story.append(Paragraph("6. DISCLAIMER", heading_style))
        
        disclaimer_text = f"""This tool was created by {TOOL_AUTHOR} for ethical cybersecurity research purposes only.
        
This report is generated automatically by {TOOL_NAME} and is intended for authorized security testing purposes. 
The information contained in this report should be used responsibly and only on systems you have explicit 
permission to test.

The authors and contributors of this tool are not responsible for any misuse or damage caused by this tool. 
Always ensure you have proper authorization before conducting any security assessments.

© 2025 {TOOL_AUTHOR} - All Rights Reserved.
"""
        story.append(Paragraph(disclaimer_text, body_style))
        story.append(Spacer(1, 24))
        
        # Footer note
        story.append(Paragraph(f"<i>{footer_text}</i>", body_style))
        
        # Build PDF with footer on every page
        def add_footer(canvas, doc):
            canvas.saveState()
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(colors.grey)
            canvas.drawString(0.75*inch, 0.5*inch, footer_text)
            canvas.restoreState()
        
        doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
        
        print(f"[+] Report generated: {filepath}")
        return filepath
        
    except Exception as e:
        print(f"[ERROR] PDF generation failed: {e}")
        return ""
