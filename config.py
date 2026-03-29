# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
Configuration loader for RedTeam-Agent
Author: Abdulwahab Hamoud Salah
"""

import os
from dotenv import load_dotenv

TOOL_AUTHOR  = "Abdulwahab Hamoud Salah"
TOOL_NAME    = "RedTeam-Agent"
TOOL_VERSION = "1.0.0"


def load_config():
    """
    Load configuration from .env file
    Arabic: تحميل متغيرات البيئة والتحقق من مفاتيح API
    """
    try:
        load_dotenv()
        config = {
            'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY', ''),
            'openai_api_key':    os.getenv('OPENAI_API_KEY', ''),
            'shodan_api_key':    os.getenv('SHODAN_API_KEY', ''),
            'tool_author':       TOOL_AUTHOR,
            'tool_name':         TOOL_NAME,
            'tool_version':      TOOL_VERSION
        }
        warnings = []
        if not config['anthropic_api_key'] and not config['openai_api_key']:
            warnings.append("⚠ WARNING: No API key found (ANTHROPIC_API_KEY or OPENAI_API_KEY)")
            warnings.append("  Analysis features will be limited")
        if not config['shodan_api_key']:
            warnings.append("⚠ INFO: SHODAN_API_KEY not set (optional)")
        return config, warnings
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}")
        return {
            'anthropic_api_key': '', 'openai_api_key': '',
            'shodan_api_key': '', 'tool_author': TOOL_AUTHOR,
            'tool_name': TOOL_NAME, 'tool_version': TOOL_VERSION
        }, [f"Error loading config: {e}"]


def get_api_key():
    """
    Arabic: إرجاع أول مفتاح API متاح
    """
    config, _ = load_config()
    if config['anthropic_api_key']:
        return 'anthropic', config['anthropic_api_key']
    elif config['openai_api_key']:
        return 'openai', config['openai_api_key']
    else:
        return None, None


def print_startup_message():
    """
    Arabic: عرض رسالة بدء التشغيل
    """
    print(f"[+] {TOOL_NAME} v{TOOL_VERSION} | Author: {TOOL_AUTHOR}")
