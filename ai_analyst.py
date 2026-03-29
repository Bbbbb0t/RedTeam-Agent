# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
Analysis Module for RedTeam-Agent
Author: Abdulwahab Hamoud Salah
"""

import os
import time
import json
from typing import Dict
from dotenv import load_dotenv

try:
    import anthropic
except ImportError:
    print("[ERROR] anthropic not installed. Run: pip install anthropic")

try:
    from openai import OpenAI
except ImportError:
    print("[ERROR] openai not installed. Run: pip install openai")

TOOL_AUTHOR = "Abdulwahab Hamoud Salah"
TOOL_NAME   = "RedTeam-Agent"


def analyze_findings(osint_data: Dict, scan_data: Dict, cve_data: list) -> Dict:
    """
    Arabic: تحليل جميع النتائج وإرجاع تقرير مفصل
    """
    analysis_result = {
        'executive_summary': '',
        'attack_surface_summary': '',
        'top_risks': [],
        'remediation_steps': [],
        'risk_score': 5,
        'analysis_success': False,
        'error': None
    }
    try:
        prompt   = build_analysis_prompt(osint_data, scan_data, cve_data)
        api_type, api_key = get_available_api()

        if api_type == 'anthropic' and api_key:
            analysis_result = analyze_with_anthropic(prompt, api_key)
        elif api_type == 'openai' and api_key:
            analysis_result = analyze_with_openai(prompt, api_key)
        else:
            print("[*] No API key — using rule-based analysis...")
            analysis_result = generate_basic_analysis(osint_data, scan_data, cve_data)

        return analysis_result
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        analysis_result['error'] = str(e)
        return generate_basic_analysis(osint_data, scan_data, cve_data)


def build_analysis_prompt(osint_data: Dict, scan_data: Dict, cve_data: list) -> str:
    """
    Arabic: بناء الطلب التحليلي من البيانات المجمعة
    """
    prompt = "You are an expert cybersecurity analyst. Analyze the following data:\n\n"
    prompt += "## OSINT:\n"

    if osint_data:
        subdomains = osint_data.get('subdomains', [])
        emails     = osint_data.get('emails', [])
        tech       = osint_data.get('technologies', {})
        ip_info    = osint_data.get('ip_info', {})

        prompt += f"- Subdomains: {len(subdomains)}\n"
        if subdomains[:10]:
            prompt += f"  {', '.join(subdomains[:10])}\n"
        prompt += f"- Emails: {len(emails)}\n"
        if emails:
            prompt += f"  {', '.join(emails[:5])}\n"
        prompt += f"- CMS: {tech.get('cms', 'Unknown')}\n"
        if tech.get('frameworks'):
            prompt += f"- Frameworks: {', '.join(tech['frameworks'])}\n"
        if tech.get('web_server'):
            prompt += f"- Web Server: {', '.join(tech['web_server'])}\n"
        prompt += f"- Server Location: {ip_info.get('country', 'Unknown')}\n"

    prompt += "\n## Port Scan:\n"
    if scan_data:
        ports = scan_data.get('ports', {})
        prompt += f"- Open ports: {len(ports)}\n"
        for port, data in list(ports.items())[:10]:
            prompt += f"  Port {port}: {data.get('service','unknown')} {data.get('version','')}\n"
        ssl = scan_data.get('ssl', {})
        if ssl.get('valid'):
            prompt += f"- SSL: Valid ({ssl.get('days_until_expiry', 0)} days left)\n"
        h = scan_data.get('security_headers', {})
        prompt += f"- Security Headers: {h.get('score', 0)}/{h.get('total', 7)}\n"

    prompt += "\n## CVE Findings:\n"
    if cve_data:
        prompt += f"- Total CVEs: {len(cve_data)}\n"
        for cve in cve_data[:5]:
            prompt += f"  {cve.get('cve_id','?')} - {cve.get('severity','?')} (Score: {cve.get('score','N/A')})\n"
    else:
        prompt += "- No CVEs found\n"

    prompt += """
Return ONLY valid JSON with these exact keys:
{
    "executive_summary": "...",
    "attack_surface_summary": "...",
    "top_risks": ["risk1", "risk2", "risk3"],
    "remediation_steps": ["step1", "step2", "step3", "step4", "step5"],
    "risk_score": 0
}
"""
    return prompt


def analyze_with_anthropic(prompt: str, api_key: str) -> Dict:
    """
    Arabic: إرسال التحليل عبر مفتاح API وإرجاع النتائج
    """
    try:
        client  = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        result = parse_response(message.content[0].text)
        result['analysis_success'] = True
        return result
    except Exception as e:
        print(f"[ERROR] Analysis request failed: {e}")
        return _failed_result(str(e))


def analyze_with_openai(prompt: str, api_key: str) -> Dict:
    """
    Arabic: إرسال التحليل عبر مفتاح API وإرجاع النتائج
    """
    try:
        client   = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Respond with JSON only."},
                {"role": "user",   "content": prompt}
            ],
            max_tokens=2000
        )
        result = parse_response(response.choices[0].message.content)
        result['analysis_success'] = True
        return result
    except Exception as e:
        print(f"[ERROR] Analysis request failed: {e}")
        return _failed_result(str(e))


def parse_response(response_text: str) -> Dict:
    """
    Arabic: استخراج JSON من نص الرد
    """
    try:
        start = response_text.find('{')
        end   = response_text.rfind('}') + 1
        if start >= 0 and end > start:
            data = json.loads(response_text[start:end])
            return {
                'executive_summary':     data.get('executive_summary', ''),
                'attack_surface_summary': data.get('attack_surface_summary', ''),
                'top_risks':             data.get('top_risks', []),
                'remediation_steps':     data.get('remediation_steps', []),
                'risk_score':            min(10, max(0, data.get('risk_score', 5))),
                'analysis_success':      True
            }
    except Exception:
        pass
    return _failed_result("Parse error")


def _failed_result(error: str) -> Dict:
    return {
        'executive_summary': 'Analysis could not be completed',
        'attack_surface_summary': '',
        'top_risks': ['Review findings manually'],
        'remediation_steps': ['Manual review required'],
        'risk_score': 5,
        'analysis_success': False,
        'error': error
    }


def generate_basic_analysis(osint_data: Dict, scan_data: Dict, cve_data: list) -> Dict:
    """
    Arabic: تحليل قائم على القواعد بدون مفتاح API
    """
    risks       = []
    remediation = []
    risk_score  = 5

    try:
        critical = [c for c in cve_data if c.get('severity') in ['CRITICAL', 'HIGH']]
        if critical:
            risks.append(f"Found {len(critical)} critical/high severity CVEs")
            remediation.append("Apply security patches immediately")
            risk_score += 2

        headers = scan_data.get('security_headers', {})
        if headers.get('score', 0) < headers.get('total', 7) / 2:
            risks.append("Missing critical HTTP security headers")
            remediation.append("Implement HSTS, CSP, X-Frame-Options")
            risk_score += 1

        ssl = scan_data.get('ssl', {})
        if ssl.get('expires_soon'):
            risks.append("SSL certificate expiring soon")
            remediation.append("Renew SSL certificate before expiration")
            risk_score += 1
        if ssl.get('self_signed'):
            risks.append("Self-signed SSL certificate detected")
            remediation.append("Replace with certificate from trusted CA")
            risk_score += 1

        ports          = scan_data.get('ports', {})
        dangerous_ports = [21, 23, 3306, 5432, 6379, 27017]
        exposed        = [p for p in ports.keys() if p in dangerous_ports]
        if exposed:
            risks.append(f"Dangerous services exposed on ports: {exposed}")
            remediation.append("Restrict access to database and admin services")
            risk_score += 1

        if not remediation:
            remediation = [
                "Regularly update all software and dependencies",
                "Implement defense-in-depth security",
                "Conduct regular security assessments",
                "Monitor logs for suspicious activity",
                "Maintain secure backup procedures"
            ]
        if not risks:
            risks      = ["No critical issues identified automatically"]
            risk_score = 3

        summary = (f"Assessment completed. Found {len(cve_data)} potential vulnerabilities. "
                   f"Overall risk level: {risk_score}/10. "
                   "Review findings and apply recommended measures.")

        return {
            'executive_summary':     summary,
            'attack_surface_summary': f"Scanned {len(ports)} open ports, {len(cve_data)} CVEs identified",
            'top_risks':             risks[:3],
            'remediation_steps':     remediation[:5],
            'risk_score':            min(10, risk_score),
            'analysis_success':      True
        }
    except Exception as e:
        return _failed_result(str(e))


def get_available_api():
    """
    Arabic: التحقق من مفاتيح API المتاحة
    """
    try:
        load_dotenv()
        anthropic_key = os.getenv('ANTHROPIC_API_KEY', '')
        openai_key    = os.getenv('OPENAI_API_KEY', '')
        if anthropic_key:
            return 'anthropic', anthropic_key
        elif openai_key:
            return 'openai', openai_key
        return None, None
    except Exception:
        return None, None
