# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
Port Scanner Module for RedTeam-Agent
Port scanning, service detection, SSL checking
Author: Abdulwahab Hamoud Salah
"""

import socket
import ssl
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlparse

try:
    import nmap
except ImportError:
    print("[ERROR] python-nmap not installed. Run: pip install python-nmap")

try:
    import requests
except ImportError:
    print("[ERROR] requests not installed. Run: pip install requests")

# Tool metadata
TOOL_AUTHOR = "Abdulwahab Hamoud Salah"
TOOL_NAME = "RedTeam-Agent"


def scan_ports(ip: str, port_range: str = "1-1000") -> Dict:
    """
    Scan ports using Nmap
    
    English: Performs TCP port scan with service version detection
    Arabic: إجراء فحص المنافذ TCP مع اكتشاف إصدار الخدمة
    
    Args:
        ip: Target IP address
        port_range: Port range (e.g., "1-1000", "80,443,8080")
    
    Returns:
        Dict with port scan results
    """
    results = {}
    
    try:
        # Initialize Nmap scanner
        nm = nmap.PortScanner()
        
        # Build nmap arguments
        arguments = f"-p {port_range} -sV --open"
        
        print(f"[*] Starting Nmap scan on {ip}...")
        
        # Run the scan
        nm.scan(hosts=ip, arguments=arguments)
        
        # Parse results
        if ip in nm.all_hosts():
            host_result = nm[ip]
            
            if 'tcp' in host_result:
                for port in host_result['tcp']:
                    port_data = host_result['tcp'][port]
                    
                    results[port] = {
                        'state': port_data.get('state', 'unknown'),
                        'service': port_data.get('name', 'unknown'),
                        'version': port_data.get('version', ''),
                        'product': port_data.get('product', ''),
                        'banner': f"{port_data.get('product', '')} {port_data.get('version', '')}".strip()
                    }
        
        print(f"[+] Scanned {len(results)} open ports")
        return results
        
    except Exception as e:
        print(f"[ERROR] Port scan failed: {e}")
        # Fallback: Basic socket scan
        return basic_port_scan(ip, port_range)


def basic_port_scan(ip: str, port_range: str = "1-1000") -> Dict:
    """
    Fallback basic port scan using sockets
    
    English: Simple TCP connect scan when Nmap is unavailable
    Arabic: فحص TCP بسيط عند عدم توفر Nmap
    
    Args:
        ip: Target IP address
        port_range: Port range string
    
    Returns:
        Dict with open ports
    """
    results = {}
    
    try:
        # Parse port range
        ports_to_scan = []
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports_to_scan = list(range(start, min(end + 1, 1001)))  # Limit to 1000
        elif ',' in port_range:
            ports_to_scan = [int(p.strip()) for p in port_range.split(',')]
        else:
            ports_to_scan = [int(port_range)]
        
        # Common ports to always check
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                       3306, 3389, 5432, 8080, 8443]
        
        # Use common ports if range is too large
        if len(ports_to_scan) > 100:
            ports_to_scan = common_ports
        
        print(f"[*] Basic scan of {len(ports_to_scan)} ports...")
        
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    # Try to get banner
                    try:
                        sock.send(b"GET / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                    except Exception:
                        banner = ""
                    
                    results[port] = {
                        'state': 'open',
                        'service': get_service_name(port),
                        'version': '',
                        'product': '',
                        'banner': banner
                    }
                
                sock.close()
                time.sleep(0.05)  # Rate limiting
                
            except Exception:
                continue
        
        print(f"[+] Found {len(results)} open ports")
        return results
        
    except Exception as e:
        print(f"[ERROR] Basic port scan failed: {e}")
        return results


def get_service_name(port: int) -> str:
    """
    Get common service name for a port
    
    English: Returns well-known service name for standard ports
    Arabic: إرجاع اسم الخدمة المعروفة للمنافذ القياسية
    
    Args:
        port: Port number
    
    Returns:
        Service name string
    """
    services = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        993: 'imaps',
        995: 'pop3s',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        5900: 'vnc',
        6379: 'redis',
        8080: 'http-proxy',
        8443: 'https-alt',
        27017: 'mongodb'
    }
    return services.get(port, 'unknown')


def check_ssl(domain: str) -> Dict:
    """
    Check SSL certificate details
    
    English: Retrieves SSL certificate information and validity
    Arabic: استرجاع معلومات شهادة SSL وصحتها
    
    Args:
        domain: Target domain
    
    Returns:
        Dict with SSL certificate details
    """
    ssl_info = {
        'valid': False,
        'issuer': None,
        'subject': None,
        'not_before': None,
        'not_after': None,
        'days_until_expiry': None,
        'expires_soon': False,
        'self_signed': False,
        'error': None
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    ssl_info['valid'] = True
                    
                    # Parse issuer
                    issuer_items = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['issuer'] = issuer_items.get('organizationName', 
                                   issuer_items.get('commonName', 'Unknown'))
                    
                    # Parse subject
                    subject_items = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['subject'] = subject_items.get('commonName', 'Unknown')
                    
                    # Parse dates
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    ssl_info['not_before'] = not_before.isoformat()
                    ssl_info['not_after'] = not_after.isoformat()
                    
                    # Calculate days until expiry
                    days_left = (not_after - datetime.now()).days
                    ssl_info['days_until_expiry'] = days_left
                    
                    # Check if expires soon (< 30 days)
                    ssl_info['expires_soon'] = days_left < 30
                    
                    # Check if self-signed
                    ssl_info['self_signed'] = (ssl_info['issuer'] == ssl_info['subject'])
        
        return ssl_info
        
    except ssl.SSLCertVerificationError as e:
        ssl_info['error'] = f"SSL verification failed: {str(e)}"
        return ssl_info
    except Exception as e:
        ssl_info['error'] = f"SSL check failed: {str(e)}"
        return ssl_info


def check_security_headers(url: str) -> Dict:
    """
    Check HTTP security headers
    
    English: Analyzes presence and strength of security headers
    Arabic: تحليل وجود وقوة رؤوس الأمان HTTP
    
    Args:
        url: Target URL
    
    Returns:
        Dict with security header analysis
    """
    headers_check = {
        'strict_transport_security': {'status': 'MISSING', 'value': None},
        'content_security_policy': {'status': 'MISSING', 'value': None},
        'x_frame_options': {'status': 'MISSING', 'value': None},
        'x_content_type_options': {'status': 'MISSING', 'value': None},
        'x_xss_protection': {'status': 'MISSING', 'value': None},
        'referrer_policy': {'status': 'MISSING', 'value': None},
        'permissions_policy': {'status': 'MISSING', 'value': None},
        'score': 0,
        'total': 7
    }
    
    try:
        # Ensure URL has protocol
        if not url.startswith('http'):
            url = f"https://{url}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        resp_headers = response.headers
        
        # Check Strict-Transport-Security (HSTS)
        if 'strict-transport-security' in resp_headers:
            headers_check['strict_transport_security']['status'] = 'PRESENT'
            headers_check['strict_transport_security']['value'] = resp_headers['strict-transport-security']
            headers_check['score'] += 1
        
        # Check Content-Security-Policy
        if 'content-security-policy' in resp_headers:
            headers_check['content_security_policy']['status'] = 'PRESENT'
            headers_check['content_security_policy']['value'] = resp_headers['content-security-policy']
            headers_check['score'] += 1
        
        # Check X-Frame-Options
        if 'x-frame-options' in resp_headers:
            headers_check['x_frame_options']['status'] = 'PRESENT'
            headers_check['x_frame_options']['value'] = resp_headers['x-frame-options']
            headers_check['score'] += 1
        
        # Check X-Content-Type-Options
        if 'x-content-type-options' in resp_headers:
            val = resp_headers['x-content-type-options'].lower()
            if val == 'nosniff':
                headers_check['x_content_type_options']['status'] = 'PRESENT'
                headers_check['score'] += 1
            else:
                headers_check['x_content_type_options']['status'] = 'WEAK'
        
        # Check X-XSS-Protection
        if 'x-xss-protection' in resp_headers:
            headers_check['x_xss_protection']['status'] = 'PRESENT'
            headers_check['x_xss_protection']['value'] = resp_headers['x-xss-protection']
            headers_check['score'] += 1
        
        # Check Referrer-Policy
        if 'referrer-policy' in resp_headers:
            headers_check['referrer_policy']['status'] = 'PRESENT'
            headers_check['referrer_policy']['value'] = resp_headers['referrer-policy']
            headers_check['score'] += 1
        
        # Check Permissions-Policy (formerly Feature-Policy)
        if 'permissions-policy' in resp_headers or 'feature-policy' in resp_headers:
            headers_check['permissions_policy']['status'] = 'PRESENT'
            headers_check['score'] += 1
        
        return headers_check
        
    except Exception as e:
        print(f"[ERROR] Security headers check failed: {e}")
        return headers_check


def run_full_scan(target: str, port_range: str = "1-1000") -> Dict:
    """
    Run complete security scan
    
    English: Executes all scanning functions and returns consolidated results
    Arabic: تنفيذ جميع وظائف الفحص وإرجاع النتائج الموحدة
    
    Args:
        target: Target domain or IP
        port_range: Port range to scan
    
    Returns:
        Dict with all scan findings
    """
    results = {
        'ports': {},
        'ssl': {},
        'security_headers': {}
    }
    
    try:
        # Resolve domain to IP if needed
        ip = target
        if not target.replace('.', '').isdigit():
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                pass
        
        # Port scan
        print("[*] Starting port scan...")
        results['ports'] = scan_ports(ip, port_range)
        
        time.sleep(1)  # Rate limiting
        
        # SSL check (only if HTTPS might be available)
        if 443 in results['ports'] or 8443 in results['ports']:
            print("[*] Checking SSL certificate...")
            results['ssl'] = check_ssl(target)
        
        # Security headers check
        print("[*] Checking security headers...")
        results['security_headers'] = check_security_headers(target)
        score = results['security_headers'].get('score', 0)
        total = results['security_headers'].get('total', 7)
        print(f"[+] Security headers score: {score}/{total}")
        
        return results
        
    except Exception as e:
        print(f"[ERROR] Full scan failed: {e}")
        return results
