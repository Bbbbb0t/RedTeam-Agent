# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
CVE Lookup Module for RedTeam-Agent
Queries NIST NVD API for vulnerability information
Author: Abdulwahab Hamoud Salah
"""

import time
from typing import Dict, List, Optional
import requests

# Tool metadata
TOOL_AUTHOR = "Abdulwahab Hamoud Salah"
TOOL_NAME = "RedTeam-Agent"

# NIST NVD API v2.0 endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cves(service_name: str, version: str = "") -> List[Dict]:
    """
    Look up CVEs for a specific service and version
    
    English: Queries NIST NVD API for vulnerabilities matching service/version
    Arabic: الاستعلام عن الثغرات من NIST NVD API للخدمة والإصدار
    
    Args:
        service_name: Name of the service (e.g., "apache", "nginx")
        version: Version string (e.g., "2.4.49")
    
    Returns:
        List of CVE dictionaries with details
    """
    cves = []
    
    try:
        # Build search keyword
        keyword = service_name.strip()
        if version and version.strip():
            keyword = f"{keyword} {version.strip()}"
        
        # Query NVD API
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 5,  # Limit to top 5
            'startIndex': 0
        }
        
        headers = {
            'User-Agent': f'{TOOL_NAME}/1.0'
        }
        
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities'][:5]:  # Top 5 only
                    cve_data = vuln.get('cve', {})
                    
                    # Extract CVSS score
                    cvss_score = None
                    cvss_severity = 'UNKNOWN'
                    
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    elif 'cvssMetricV3' in metrics:
                        cvss_data = metrics['cvssMetricV3'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_severity = cvss_data.get('severity', 'UNKNOWN')
                    
                    # Extract description
                    descriptions = cve_data.get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    cve_info = {
                        'cve_id': cve_data.get('id', 'Unknown'),
                        'severity': cvss_severity,
                        'score': cvss_score,
                        'description': description[:500] if description else 'No description available',
                        'published': cve_data.get('published', ''),
                        'service': service_name,
                        'version': version
                    }
                    
                    cves.append(cve_info)
        
        # Rate limiting - NVD API allows 5 requests per 30 seconds without API key
        time.sleep(6)
        
        return cves
        
    except Exception as e:
        print(f"[ERROR] CVE lookup failed for {service_name}: {e}")
        return cves


def batch_lookup(services_dict: Dict) -> List[Dict]:
    """
    Look up CVEs for multiple services
    
    English: Performs batch CVE lookup for all discovered services
    Arabic: إجراء بحث جماعي عن الثغرات لجميع الخدمات المكتشفة
    
    Args:
        services_dict: Dict from scanner with port/service info
                      Format: {port: {service, version, ...}}
    
    Returns:
        Consolidated list of all CVEs found
    """
    all_cves = []
    
    try:
        print("[*] Starting CVE lookup for discovered services...")
        
        # Extract unique service/version pairs
        services_to_check = set()
        
        for port, data in services_dict.items():
            service = data.get('service', '').lower()
            version = data.get('version', '').strip()
            product = data.get('product', '').strip()
            
            # Skip unknown services
            if not service or service == 'unknown':
                continue
            
            # Use product name if available
            if product:
                services_to_check.add((product.lower(), version))
            else:
                services_to_check.add((service, version))
        
        print(f"[*] Checking {len(services_to_check)} service(s) for CVEs...")
        
        # Look up CVEs for each service
        for service_name, version in services_to_check:
            print(f"  [*] Looking up CVEs for: {service_name} {version}")
            
            cves = lookup_cves(service_name, version)
            all_cves.extend(cves)
            
            # Rate limiting between requests
            time.sleep(1)
        
        # Sort by severity
        severity_order = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1}
        all_cves.sort(key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 0), reverse=True)
        
        print(f"[+] Found {len(all_cves)} total CVEs")
        
        return all_cves
        
    except Exception as e:
        print(f"[ERROR] Batch CVE lookup failed: {e}")
        return all_cves


def get_cve_summary(cves: List[Dict]) -> Dict:
    """
    Generate summary statistics for CVE findings
    
    English: Creates summary of CVE counts by severity
    Arabic: إنشاء ملخص لعدد الثغرات حسب الخطورة
    
    Args:
        cves: List of CVE dictionaries
    
    Returns:
        Dict with summary statistics
    """
    summary = {
        'total': len(cves),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'unknown': 0,
        'average_score': 0
    }
    
    try:
        total_score = 0
        scored_count = 0
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN').upper()
            score = cve.get('score')
            
            if severity == 'CRITICAL':
                summary['critical'] += 1
            elif severity == 'HIGH':
                summary['high'] += 1
            elif severity == 'MEDIUM':
                summary['medium'] += 1
            elif severity == 'LOW':
                summary['low'] += 1
            else:
                summary['unknown'] += 1
            
            if score is not None:
                total_score += score
                scored_count += 1
        
        if scored_count > 0:
            summary['average_score'] = round(total_score / scored_count, 2)
        
        return summary
        
    except Exception as e:
        print(f"[ERROR] CVE summary failed: {e}")
        return summary
