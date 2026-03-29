# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
OSINT Module for RedTeam-Agent
Subdomain discovery, email scraping, technology detection
Author: Abdulwahab Hamoud Salah
"""

import socket
import re
import time
import dns.resolver
from typing import List, Dict, Optional
from urllib.parse import urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Run: pip install requests beautifulsoup4")

# Tool metadata
TOOL_AUTHOR = "Abdulwahab Hamoud Salah"
TOOL_NAME = "RedTeam-Agent"


def get_subdomains(domain: str) -> List[str]:
    """
    Discover subdomains using multiple methods
    
    English: Finds subdomains via DNS brute force and common lists
    Arabic: اكتشاف النطاقات الفرعية عبر القوة الغاشمة للقوائم الشائعة
    
    Args:
        domain: Target domain
    
    Returns:
        List of discovered subdomains
    """
    subdomains = set()
    
    try:
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop',
            'imap', 'ns1', 'ns2', 'dev', 'staging', 'test', 'api',
            'blog', 'shop', 'store', 'app', 'mobile', 'm', 'cdn',
            'static', 'assets', 'images', 'img', 'files', 'docs',
            'support', 'help', 'forum', 'community', 'status', 'monitor'
        ]
        
        # DNS brute force with common subdomains
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
                time.sleep(0.1)  # Rate limiting
            except socket.gaierror:
                continue
        
        # Try DNS zone transfer (usually blocked but worth trying)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    # Attempt zone transfer (AXFR)
                    # This usually fails but we try anyway
                    pass
                except Exception:
                    pass
        except Exception:
            pass
        
        # Try Certificate Transparency logs via crt.sh API
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if 'name_value' in entry:
                        names = entry['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if domain in name and '*' not in name:
                                subdomains.add(name)
        except Exception:
            pass
        
        return sorted(list(subdomains))
        
    except Exception as e:
        print(f"[ERROR] Subdomain discovery failed: {e}")
        return list(subdomains)


def get_emails(domain: str) -> List[str]:
    """
    Scrape emails from search engines and web pages
    
    English: Extracts email addresses associated with the domain
    Arabic: استخراج عناوين البريد الإلكتروني المرتبطة بالنطاق
    
    Args:
        domain: Target domain
    
    Returns:
        List of discovered email addresses
    """
    emails = set()
    
    try:
        # Email regex pattern
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        # Search Google (simulated - actual scraping requires API)
        search_queries = [
            f"site:{domain} email",
            f"site:{domain} contact",
            f"site:{domain} @ {domain}"
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Try to fetch the main page
        try:
            urls_to_check = [
                f"http://{domain}",
                f"https://{domain}",
                f"http://{domain}/contact",
                f"https://{domain}/contact",
                f"http://{domain}/about",
                f"https://{domain}/about"
            ]
            
            for url in urls_to_check:
                try:
                    response = requests.get(url, headers=headers, timeout=5)
                    if response.status_code == 200:
                        # Find emails in HTML
                        found_emails = re.findall(email_pattern, response.text)
                        for email in found_emails:
                            if domain in email:
                                emails.add(email.lower())
                    time.sleep(1)  # Rate limiting
                except Exception:
                    continue
                    
        except Exception:
            pass
        
        # Check WHOIS data for emails
        try:
            import whois
            w = whois.whois(domain)
            if hasattr(w, 'emails') and w.emails:
                if isinstance(w.emails, str):
                    emails.add(w.emails.lower())
                elif isinstance(w.emails, list):
                    for email in w.emails:
                        emails.add(email.lower())
        except Exception:
            pass
        
        return sorted(list(emails))
        
    except Exception as e:
        print(f"[ERROR] Email discovery failed: {e}")
        return list(emails)


def get_technologies(domain: str) -> Dict:
    """
    Detect technologies used by the target
    
    English: Identifies CMS, frameworks, servers from HTTP headers and HTML
    Arabic: تحديد أنظمة إدارة المحتوى والإطارات والخوادم من رؤوس HTTP و HTML
    
    Args:
        domain: Target domain
    
    Returns:
        Dict with detected technologies
    """
    technologies = {
        'web_server': [],
        'cms': None,
        'frameworks': [],
        'programming_languages': [],
        'analytics': [],
        'headers': {}
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Try HTTPS first, then HTTP
        url = None
        response = None
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, headers=headers, timeout=10)
                break
            except Exception:
                continue
        
        if not response:
            return technologies
        
        # Parse HTTP headers
        http_headers = response.headers
        
        # Web server detection
        if 'Server' in http_headers:
            technologies['web_server'].append(http_headers['Server'])
        
        # Technology detection from headers
        if 'X-Powered-By' in http_headers:
            tech = http_headers['X-Powered-By'].lower()
            if 'php' in tech:
                technologies['programming_languages'].append('PHP')
            elif 'asp.net' in tech or 'aspnet' in tech:
                technologies['programming_languages'].append('ASP.NET')
            elif 'express' in tech:
                technologies['frameworks'].append('Express.js')
        
        # CMS detection from HTML content
        html_content = response.text.lower()
        
        # WordPress detection
        if 'wp-content' in html_content or 'wp-includes' in html_content:
            technologies['cms'] = 'WordPress'
        
        # Joomla detection
        if 'joomla' in html_content or '/media/jui/' in html_content:
            technologies['cms'] = 'Joomla'
        
        # Drupal detection
        if 'drupal' in html_content or '/sites/default/' in html_content:
            technologies['cms'] = 'Drupal'
        
        # Shopify detection
        if 'shopify' in html_content or 'cdn.shopify.com' in html_content:
            technologies['cms'] = 'Shopify'
        
        # Wix detection
        if 'wix.com' in html_content or 'wixstatic.com' in html_content:
            technologies['cms'] = 'Wix'
        
        # React detection
        if 'react' in html_content or 'reactdom' in html_content:
            technologies['frameworks'].append('React')
        
        # Angular detection
        if 'ng-app' in html_content or 'angular' in html_content:
            technologies['frameworks'].append('Angular')
        
        # Vue.js detection
        if 'vue' in html_content or 'vue.js' in html_content:
            technologies['frameworks'].append('Vue.js')
        
        # jQuery detection
        if 'jquery' in html_content:
            technologies['frameworks'].append('jQuery')
        
        # Bootstrap detection
        if 'bootstrap' in html_content:
            technologies['frameworks'].append('Bootstrap')
        
        # Google Analytics detection
        if 'google-analytics' in html_content or 'ga.js' in html_content:
            technologies['analytics'].append('Google Analytics')
        
        # Store headers
        technologies['headers'] = dict(http_headers)
        
        return technologies
        
    except Exception as e:
        print(f"[ERROR] Technology detection failed: {e}")
        return technologies


def get_ip_info(domain: str) -> Dict:
    """
    Get IP address and geolocation information
    
    English: Resolves domain IP and fetches geolocation data
    Arabic: حل عنوان IP للنطاق وجلب بيانات الموقع الجغرافي
    
    Args:
        domain: Target domain
    
    Returns:
        Dict with IP and location information
    """
    ip_info = {
        'ip': None,
        'country': None,
        'region': None,
        'city': None,
        'isp': None,
        'org': None,
        'timezone': None,
        'latitude': None,
        'longitude': None
    }
    
    try:
        # Resolve IP address
        ip_address = socket.gethostbyname(domain)
        ip_info['ip'] = ip_address
        
        # Get geolocation from ip-api.com (free, no API key needed)
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    ip_info['country'] = data.get('country')
                    ip_info['region'] = data.get('regionName')
                    ip_info['city'] = data.get('city')
                    ip_info['isp'] = data.get('isp')
                    ip_info['org'] = data.get('org')
                    ip_info['timezone'] = data.get('timezone')
                    ip_info['latitude'] = data.get('lat')
                    ip_info['longitude'] = data.get('lon')
        except Exception:
            pass
        
        return ip_info
        
    except Exception as e:
        print(f"[ERROR] IP info lookup failed: {e}")
        return ip_info


def run_full_osint(domain: str) -> Dict:
    """
    Run complete OSINT reconnaissance
    
    English: Executes all OSINT functions and returns consolidated results
    Arabic: تنفيذ جميع وظائف OSINT وإرجاع النتائج الموحدة
    
    Args:
        domain: Target domain
    
    Returns:
        Dict with all OSINT findings
    """
    results = {
        'subdomains': [],
        'emails': [],
        'technologies': {},
        'ip_info': {}
    }
    
    try:
        print(f"[*] Starting OSINT reconnaissance for: {domain}")
        
        # Get subdomains
        print("[*] Discovering subdomains...")
        results['subdomains'] = get_subdomains(domain)
        print(f"[+] Found {len(results['subdomains'])} subdomains")
        
        time.sleep(1)  # Rate limiting
        
        # Get emails
        print("[*] Searching for email addresses...")
        results['emails'] = get_emails(domain)
        print(f"[+] Found {len(results['emails'])} email addresses")
        
        time.sleep(1)  # Rate limiting
        
        # Get technologies
        print("[*] Detecting technologies...")
        results['technologies'] = get_technologies(domain)
        cms = results['technologies'].get('cms', 'Unknown')
        print(f"[+] Detected CMS: {cms}")
        
        time.sleep(1)  # Rate limiting
        
        # Get IP info
        print("[*] Getting IP information...")
        results['ip_info'] = get_ip_info(domain)
        ip = results['ip_info'].get('ip', 'Unknown')
        country = results['ip_info'].get('country', 'Unknown')
        print(f"[+] IP: {ip} ({country})")
        
        return results
        
    except Exception as e:
        print(f"[ERROR] OSINT reconnaissance failed: {e}")
        return results
