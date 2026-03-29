# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
Logging utility for RedTeam-Agent
Author: Abdulwahab Hamoud Salah
"""

import os
import logging
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler

console = Console()

TOOL_AUTHOR = "Abdulwahab Hamoud Salah"
TOOL_NAME   = "RedTeam-Agent"


def setup_logger(name="RedTeam-Agent", log_dir="logs"):
    """
    Arabic: إنشاء مسجل مع معالجات للطرفية والملفات
    """
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file  = os.path.join(log_dir, f"scan_{timestamp}.log")

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers = []

        console_handler = RichHandler(console=console, rich_tracebacks=True,
                                      tracebacks_show_locals=False, markup=True)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"# RedTeam-Agent | Author: {TOOL_AUTHOR}\n")
            f.write(f"# Scan started: {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        return logger

    except Exception as e:
        console.print(f"[red]ERROR setting up logger: {e}[/red]")
        return logging.getLogger(name)


def log_info(logger, message):
    try: logger.info(f"[blue]{message}[/blue]")
    except Exception: pass

def log_success(logger, message):
    try: logger.info(f"[green]✓ {message}[/green]")
    except Exception: pass

def log_warning(logger, message):
    try: logger.warning(f"[yellow]⚠ {message}[/yellow]")
    except Exception: pass

def log_error(logger, message):
    try: logger.error(f"[red]✗ {message}[/red]")
    except Exception: pass

def print_banner():
    """
    Arabic: عرض شعار الأداة مع اسم المؤلف
    """
    banner = """
╔═══════════════════════════════════════╗
║          RedTeam Agent v1.0           ║
║   Author: Abdulwahab Hamoud Salah     ║
╚═══════════════════════════════════════╝
    """
    console.print(f"[cyan]{banner}[/cyan]")
