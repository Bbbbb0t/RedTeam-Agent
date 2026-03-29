# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
Input validation and sanitization for RedTeam-Agent
Author: Abdulwahab Hamoud Salah
"""

import re
import socket
from typing import Tuple, Optional

# Tool metadata
TOOL_AUTHOR = "Abdulwahab Hamoud Salah"
TOOL_NAME = "RedTeam-Agent"


def validate_domain(domain: str) -> Tuple[bool, str]:
    """
    Validate domain format and reachability
    
    English: Checks if domain is valid format and resolvable
    Arabic: التحقق من صحة تنسيق النطاق وإمكانية الوصول إليه
    
    Args:
        domain: Domain string to validate
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    try:
        # Check if empty
        if not domain or not domain.strip():
            return False, "Domain cannot be empty"
        
        domain = domain.strip().lower()
        
        # Remove protocol if present
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('//')[1].split('/')[0]
        
        # Basic regex for domain validation
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if not re.match(domain_pattern, domain):
            return False, f"Invalid domain format: {domain}"
        
        # Check DNS resolution
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            return False, f"Domain does not resolve: {domain}"
        
        return True, ""
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def sanitize_input(input_string: str) -> str:
    """
    Sanitize input string by removing dangerous characters
    
    English: Removes shell injection and special characters
    Arabic: إزالة أحرف الحقن والأحرف الخاصة الخطرة
    
    Args:
        input_string: Raw input string
    
    Returns:
        str: Sanitized string safe for processing
    """
    try:
        if not input_string:
            return ""
        
        # Remove shell injection characters
        dangerous_chars = [
            ';', '|', '&', '$', '`', '(', ')', '{', '}', 
            '[', ']', '<', '>', '!', '\\', '\n', '\r'
        ]
        
        sanitized = input_string
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Strip whitespace
        sanitized = sanitized.strip()
        
        # Limit length
        if len(sanitized) > 253:  # Max domain length
            sanitized = sanitized[:253]
        
        return sanitized
        
    except Exception as e:
        print(f"[ERROR] Sanitization failed: {e}")
        return ""


def validate_port_range(port_range: str) -> Tuple[bool, str]:
    """
    Validate port range format
    
    English: Checks if port range is valid (e.g., "1-1000" or "80,443")
    Arabic: التحقق من صحة نطاق المنافذ
    
    Args:
        port_range: Port range string
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    try:
        if not port_range:
            return False, "Port range cannot be empty"
        
        port_range = port_range.strip()
        
        # Single port
        if port_range.isdigit():
            port = int(port_range)
            if 1 <= port <= 65535:
                return True, ""
            return False, f"Port must be between 1-65535: {port}"
        
        # Range (e.g., "1-1000")
        if '-' in port_range:
            parts = port_range.split('-')
            if len(parts) == 2:
                start, end = int(parts[0]), int(parts[1])
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    return True, ""
                return False, f"Invalid port range: {port_range}"
        
        # Comma-separated (e.g., "80,443,8080")
        if ',' in port_range:
            ports = port_range.split(',')
            for port in ports:
                if not port.isdigit() or not (1 <= int(port) <= 65535):
                    return False, f"Invalid port in list: {port}"
            return True, ""
        
        return False, f"Invalid port range format: {port_range}"
        
    except Exception as e:
        return False, f"Port validation error: {str(e)}"


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate URL format
    
    English: Checks if URL has valid format
    Arabic: التحقق من صحة تنسيق الرابط
    
    Args:
        url: URL string to validate
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    try:
        if not url:
            return False, "URL cannot be empty"
        
        url = url.strip()
        
        # Basic URL pattern
        url_pattern = r'^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$'
        
        if not re.match(url_pattern, url):
            # Try adding http://
            if not url.startswith('http'):
                url = 'http://' + url
                if re.match(url_pattern, url):
                    return True, ""
            return False, f"Invalid URL format: {url}"
        
        return True, ""
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"
