#!/usr/bin/env python3
# ╔══════════════════════════════════════════════╗
# ║   RedTeam Agent                              ║
# ║   Author  : Abdulwahab Hamoud Salah          ║
# ║   Project : Recon & Pentest Tool             ║
# ║   Rights  : All rights reserved © 2025       ║
# ╚══════════════════════════════════════════════╝

"""
RedTeam Agent - Main Entry Point
Author: Abdulwahab Hamoud Salah
"""

import sys
import argparse
import time
from datetime import datetime

from config import TOOL_AUTHOR, TOOL_NAME, TOOL_VERSION, load_config, print_startup_message
from utils.logger import setup_logger, log_info, log_success, log_warning, log_error
from utils.validator import validate_domain, sanitize_input
from modules.osint import run_full_osint
from modules.scanner import run_full_scan
from modules.cve_lookup import batch_lookup
from modules.ai_analyst import analyze_findings
from modules.report_generator import generate_pdf

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("[ERROR] rich library not installed. Run: pip install rich")
    sys.exit(1)

console = Console()


def print_detailed_banner():
    """
    Arabic: عرض الشعار الرئيسي للأداة
    """
    banner = """
╔═══════════════════════════════════════╗
║          RedTeam Agent v1.0           ║
║   Author: Abdulwahab Hamoud Salah     ║
╚═══════════════════════════════════════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")


def print_phase(phase_name: str, description: str):
    """
    Arabic: عرض فاصل المرحلة
    """
    panel = Panel(
        f"[bold white]{description}[/bold white]",
        title=f"[bold yellow]{phase_name}[/bold yellow]",
        border_style="blue",
        padding=(1, 2)
    )
    console.print(panel)


def main():
    """
    Arabic: تنسيق سير عمل الاستكشاف الكامل
    """
    print(f"[+] {TOOL_NAME} v{TOOL_VERSION} | Author: {TOOL_AUTHOR}")

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Security Reconnaissance Tool by {TOOL_AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python main.py --target example.com
  python main.py -t scanme.nmap.org --ports 1-100

Author: {TOOL_AUTHOR}
        """
    )
    parser.add_argument('-t', '--target', type=str, required=True,
                        help='Target domain or IP address to scan')
    parser.add_argument('-p', '--ports', type=str, default='1-100',
                        help='Port range to scan (default: 1-100)')
    parser.add_argument('--no-cve', action='store_true', help='Skip CVE lookup phase')
    parser.add_argument('--no-analysis', action='store_true', help='Skip analysis phase')
    parser.add_argument('--quick', action='store_true', help='Quick scan mode')

    args = parser.parse_args()
    print_detailed_banner()

    console.print("\n[bold blue][*] Loading configuration...[/bold blue]")
    config, warnings = load_config()
    for warning in warnings:
        console.print(f"  {warning}")

    target = sanitize_input(args.target)
    console.print(f"\n[bold blue][*] Target:[/bold blue] {target}")

    is_valid, error_msg = validate_domain(target)
    if not is_valid:
        console.print(f"[red][✗] Invalid target: {error_msg}[/red]")
        sys.exit(1)

    console.print(f"[green][✓] Target validated successfully[/green]")
    logger = setup_logger()
    log_info(logger, f"Starting scan on target: {target}")

    osint_data = {}
    scan_data  = {}
    cve_data   = []
    ai_analysis = {}

    try:
        # ═══════════════ PHASE 1: OSINT ═══════════════
        print_phase("PHASE 1", "OSINT Reconnaissance")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("[cyan]Discovering subdomains, emails, technologies...", total=100)
            osint_data = run_full_osint(target)
            progress.update(task, completed=100)

        log_success(logger, f"OSINT completed: {len(osint_data.get('subdomains', []))} subdomains found")

        table = Table(title="OSINT Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        table.add_row("Subdomains", str(len(osint_data.get('subdomains', []))))
        table.add_row("Emails",     str(len(osint_data.get('emails', []))))
        table.add_row("Technologies", str(len(osint_data.get('technologies', {}).get('frameworks', []))))
        console.print(table)
        time.sleep(1)

        # ═══════════════ PHASE 2: PORT SCAN ═══════════════
        print_phase("PHASE 2", "Port Scanning & Service Detection")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task(f"[cyan]Scanning ports {args.ports}...", total=100)
            scan_data = run_full_scan(target, args.ports)
            progress.update(task, completed=100)

        log_success(logger, f"Scan completed: {len(scan_data.get('ports', {}))} open ports found")

        if scan_data.get('ports'):
            port_table = Table(title="Open Ports")
            port_table.add_column("Port",    style="yellow")
            port_table.add_column("Service", style="cyan")
            port_table.add_column("Version", style="white")
            for port, info in sorted(scan_data['ports'].items()):
                port_table.add_row(str(port), info.get('service', 'unknown'),
                                   (info.get('version', '') or info.get('product', ''))[:30])
            console.print(port_table)
        time.sleep(1)

        # ═══════════════ PHASE 3: CVE ═══════════════
        if not args.no_cve and scan_data.get('ports'):
            print_phase("PHASE 3", "CVE Vulnerability Lookup")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          BarColumn(), TimeElapsedColumn(), console=console) as progress:
                task = progress.add_task("[cyan]Querying NIST NVD database...", total=100)
                cve_data = batch_lookup(scan_data['ports'])
                progress.update(task, completed=100)

            log_success(logger, f"CVE lookup completed: {len(cve_data)} vulnerabilities found")

            if cve_data:
                cve_table = Table(title="Top CVEs Found")
                cve_table.add_column("CVE ID",   style="red")
                cve_table.add_column("Severity", style="yellow")
                cve_table.add_column("Score",    style="green")
                for cve in cve_data[:5]:
                    cve_table.add_row(cve.get('cve_id', 'Unknown'),
                                      cve.get('severity', 'Unknown'),
                                      str(cve.get('score', 'N/A')))
                console.print(cve_table)
        else:
            console.print("[yellow]⊘ Skipping CVE lookup phase[/yellow]")
        time.sleep(1)

        # ═══════════════ PHASE 4: ANALYSIS ═══════════════
        if not args.no_analysis:
            print_phase("PHASE 4", "Security Analysis")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          BarColumn(), TimeElapsedColumn(), console=console) as progress:
                task = progress.add_task("[cyan]Analyzing findings...", total=100)
                ai_analysis = analyze_findings(osint_data, scan_data, cve_data)
                progress.update(task, completed=100)

            log_success(logger, "Analysis completed")

            if ai_analysis.get('analysis_success'):
                risk_score = ai_analysis.get('risk_score', 5)
                risk_color = "bold red" if risk_score >= 8 else "bold yellow" if risk_score >= 6 else "bold green"
                console.print(Panel(
                    f"[{risk_color}]Risk Score: {risk_score}/10[/{risk_color}]\n\n"
                    f"[bold]Top Risks:[/bold]\n" +
                    "\n".join([f"• {r}" for r in ai_analysis.get('top_risks', [])[:3]])
                ))
        else:
            console.print("[yellow]⊘ Skipping analysis phase[/yellow]")
            ai_analysis = {'risk_score': 5, 'executive_summary': 'Analysis skipped'}

        # ═══════════════ PHASE 5: REPORT ═══════════════
        print_phase("PHASE 5", "PDF Report Generation")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("[cyan]Generating comprehensive report...", total=100)
            report_path = generate_pdf(target, osint_data, scan_data, cve_data, ai_analysis)
            progress.update(task, completed=100)

        if report_path:
            log_success(logger, f"Report saved: {report_path}")
            console.print(f"\n[bold green][✓] Report generated: {report_path}[/bold green]")
        else:
            console.print("[red][✗] Failed to generate report[/red]")

        # ═══════════════ DONE ═══════════════
        console.print("\n" + "=" * 60)
        console.print(f"[bold green]✓ Assessment Complete![/bold green]")
        console.print(f"[bold blue]Target:[/bold blue] {target}")
        console.print(f"[bold blue]Risk Score:[/bold blue] {ai_analysis.get('risk_score', 'N/A')}/10")
        if report_path:
            console.print(f"[bold green]Report:[/bold green] {report_path}")
        console.print("=" * 60)
        log_info(logger, f"Assessment completed for {target}")

    except KeyboardInterrupt:
        console.print("\n[yellow]⊘ Scan interrupted by user[/yellow]")
        log_warning(logger, "Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red][✗] Error during assessment: {e}[/red]")
        log_error(logger, f"Assessment failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FATAL ERROR] {e}")
        sys.exit(1)
