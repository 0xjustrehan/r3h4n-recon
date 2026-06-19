#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# RECON ALL — Main Pipeline Orchestrator
# Chains every scanner feature into one automated command.
# ═══════════════════════════════════════════════════════════════
import os
import sys
import time
import signal
import traceback
from typing import Dict, List, Any

# Ensure the parent directory is in sys.path for relative imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import PipelineConfig, collect_all_inputs, detect_sshcracker
from utils import (
    print_banner, print_phase, print_phase_done, print_phase_skip,
    print_phase_fail, print_final_report,
    extract_unique_ips, extract_root_domains, filter_by_port,
    strip_port, read_lines, write_results, HUNTER_PATHS,
)

# Scanner imports
from scanner.masscan_scan import run_masscan
from scanner.web_checker import run_web_checker
from scanner.reverse_ip import run_reverse_ip
from scanner.subdomain import run_subdomain_finder
from scanner.domain2ip import run_domain2ip
from scanner.cms_checker import run_cms_checker
from scanner.shell_finder import run_shell_finder
from scanner.api_hunter import run_api_hunter
from scanner.nla_checker import run_nla_checker
from scanner.ssh_scanner import run_ssh_port_scan, run_ssh_cracker

# ═══════════════════════════════════════════════════════════════
# GLOBALS
# ═══════════════════════════════════════════════════════════════
TOTAL_PHASES = 11
_interrupted = False


def _signal_handler(signum, frame):
    global _interrupted
    if _interrupted:
        print("\n  🛑  Force quit. Partial results saved.")
        sys.exit(1)
    _interrupted = True
    print("\n  ⚠️  Ctrl+C detected — finishing current phase then stopping...")
    print("       Press Ctrl+C again to force quit immediately.")


# ═══════════════════════════════════════════════════════════════
# PIPELINE
# ═══════════════════════════════════════════════════════════════
def run_pipeline(config: PipelineConfig):
    """Run the full recon pipeline."""
    global _interrupted

    report: Dict[str, Dict[str, Any]] = {}
    pipeline_start = time.time()

    # Track accumulated data across phases
    masscan_results: List[str] = []         # IP:Port from masscan
    web_live: List[str] = []                # Live targets from web checker
    all_domains: List[str] = []             # All discovered domains
    all_ips: List[str] = []                 # All unique IPs
    rdp_targets: List[str] = []             # Targets on port 3389

    # ══════════════════════════════════════════════════════════
    # PHASE 1: MASSCAN
    # ══════════════════════════════════════════════════════════
    if not _interrupted:
        print_phase(1, TOTAL_PHASES, "MASSCAN — Port Scanning", "🔍")
        t0 = time.time()

        if config.masscan_bin == "__prescan__":
            # User provided pre-scanned results
            print("  📄  Using pre-scanned results file...")
            masscan_results = read_lines(config.targets_file)
            elapsed = time.time() - t0
            print_phase_done("Masscan (pre-scanned)", len(masscan_results), elapsed)
            report["1. Masscan"] = {"count": len(masscan_results), "elapsed": elapsed, "status": "done"}
        elif not config.masscan_bin:
            print_phase_skip("Masscan", "masscan binary not found")
            report["1. Masscan"] = {"count": 0, "elapsed": 0, "status": "skipped"}
        else:
            try:
                masscan_results = run_masscan(
                    config.targets_file, config.ports, config.rate,
                    config.masscan_bin, config.output_dir
                )
                elapsed = time.time() - t0
                print_phase_done("Masscan", len(masscan_results), elapsed)
                report["1. Masscan"] = {"count": len(masscan_results), "elapsed": elapsed, "status": "done"}
            except Exception as e:
                elapsed = time.time() - t0
                print_phase_fail("Masscan", str(e))
                report["1. Masscan"] = {"count": 0, "elapsed": elapsed, "status": "failed"}

    if not masscan_results:
        print("  ⚠️  No masscan results — pipeline cannot continue without targets.")
        print("       Provide a pre-scanned results file or fix masscan.")
        total_time = time.time() - pipeline_start
        print_final_report(report, config.output_dir, total_time)
        return

    # Extract data for subsequent phases
    all_ips = extract_unique_ips(masscan_results)
    web_targets = filter_by_port(masscan_results, [80, 443, 8080, 8443])
    rdp_targets = filter_by_port(masscan_results, [3389])

    # If no web ports found, use all results for web checker
    if not web_targets:
        web_targets = masscan_results

    # ══════════════════════════════════════════════════════════
    # PHASE 2: WEB CHECKER (Live Check)
    # ══════════════════════════════════════════════════════════
    if not _interrupted:
        print_phase(2, TOTAL_PHASES, "WEB CHECKER — Live Detection", "🌐")
        t0 = time.time()
        try:
            web_live = run_web_checker(
                web_targets, config.threads, config.timeout, config.output_dir
            )
            elapsed = time.time() - t0
            print_phase_done("Web Checker", len(web_live), elapsed)
            report["2. Web Checker"] = {"count": len(web_live), "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("Web Checker", str(e))
            report["2. Web Checker"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
            # Fall back to using masscan web targets as "live"
            web_live = web_targets

    # ══════════════════════════════════════════════════════════
    # PHASE 3: REVERSE IP (IP → Domain)
    # ══════════════════════════════════════════════════════════
    reverse_domains: List[str] = []
    if not _interrupted:
        print_phase(3, TOTAL_PHASES, "REVERSE IP — Domain Discovery", "🌐")
        t0 = time.time()
        try:
            reverse_domains = run_reverse_ip(
                all_ips, config.threads, config.api_keys, config.output_dir
            )
            elapsed = time.time() - t0
            print_phase_done("Reverse IP", len(reverse_domains), elapsed)
            report["3. Reverse IP"] = {"count": len(reverse_domains), "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("Reverse IP", str(e))
            report["3. Reverse IP"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    else:
        report["3. Reverse IP"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # ══════════════════════════════════════════════════════════
    # PHASE 4: SUBDOMAIN FINDER
    # ══════════════════════════════════════════════════════════
    subdomains: List[str] = []
    if not _interrupted and reverse_domains:
        print_phase(4, TOTAL_PHASES, "SUBDOMAIN FINDER — Enumeration", "🌐")
        t0 = time.time()
        try:
            root_domains = sorted(extract_root_domains(reverse_domains))
            if root_domains:
                print(f"  📋  {len(root_domains)} unique root domains to enumerate")
                subdomains = run_subdomain_finder(
                    root_domains, config.threads, config.output_dir
                )
                elapsed = time.time() - t0
                print_phase_done("Subdomain Finder", len(subdomains), elapsed)
                report["4. Subdomain Finder"] = {"count": len(subdomains), "elapsed": elapsed, "status": "done"}
            else:
                elapsed = time.time() - t0
                print_phase_skip("Subdomain Finder", "no root domains extracted")
                report["4. Subdomain Finder"] = {"count": 0, "elapsed": elapsed, "status": "skipped"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("Subdomain Finder", str(e))
            report["4. Subdomain Finder"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    elif not reverse_domains:
        print_phase_skip("Subdomain Finder", "no domains from Reverse IP")
        report["4. Subdomain Finder"] = {"count": 0, "elapsed": 0, "status": "skipped"}
    else:
        report["4. Subdomain Finder"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # Merge all discovered domains
    all_domains = sorted(set(reverse_domains + subdomains))

    # ══════════════════════════════════════════════════════════
    # PHASE 5: DOMAIN → IP
    # ══════════════════════════════════════════════════════════
    domain_ip_map: Dict[str, str] = {}
    if not _interrupted and all_domains:
        print_phase(5, TOTAL_PHASES, "DOMAIN → IP — Resolution", "🌐")
        t0 = time.time()
        try:
            domain_ip_map = run_domain2ip(
                all_domains, config.threads, config.output_dir
            )
            elapsed = time.time() - t0
            print_phase_done("Domain→IP", len(domain_ip_map), elapsed)
            report["5. Domain→IP"] = {"count": len(domain_ip_map), "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("Domain→IP", str(e))
            report["5. Domain→IP"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    elif not all_domains:
        print_phase_skip("Domain→IP", "no domains discovered")
        report["5. Domain→IP"] = {"count": 0, "elapsed": 0, "status": "skipped"}
    else:
        report["5. Domain→IP"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # Build the target list for domain-based scanners
    # Use web_live (already confirmed alive) + all_domains
    scan_domains = sorted(set(
        [strip_port(t) for t in web_live] + all_domains
    ))
    # Filter out raw IPs — keep only actual domains for domain-based scanners
    domain_targets = [d for d in scan_domains if not d.replace(".", "").isdigit()]
    if not domain_targets:
        # Fall back to web_live as-is
        domain_targets = [strip_port(t) for t in web_live if not strip_port(t).replace(".", "").isdigit()]

    # ══════════════════════════════════════════════════════════
    # PHASE 6: CMS CHECKER
    # ══════════════════════════════════════════════════════════
    cms_results: Dict[str, List[str]] = {}
    if not _interrupted and domain_targets:
        print_phase(6, TOTAL_PHASES, "CMS CHECKER — Fingerprinting", "🔍")
        t0 = time.time()
        try:
            cms_results = run_cms_checker(
                domain_targets, config.threads, config.output_dir
            )
            total_cms = sum(len(v) for v in cms_results.values())
            elapsed = time.time() - t0
            print_phase_done("CMS Checker", total_cms, elapsed)
            report["6. CMS Checker"] = {"count": total_cms, "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("CMS Checker", str(e))
            report["6. CMS Checker"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    elif not domain_targets:
        print_phase_skip("CMS Checker", "no domain targets")
        report["6. CMS Checker"] = {"count": 0, "elapsed": 0, "status": "skipped"}
    else:
        report["6. CMS Checker"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # ══════════════════════════════════════════════════════════
    # PHASE 7: SHELL FINDER
    # ══════════════════════════════════════════════════════════
    shells_found: List[str] = []
    if not _interrupted and domain_targets:
        print_phase(7, TOTAL_PHASES, "SHELL FINDER — Web Shell Detection", "🐚")
        t0 = time.time()
        try:
            shells_found = run_shell_finder(
                domain_targets, config.threads,
                config.shell_paths_file, config.output_dir
            )
            elapsed = time.time() - t0
            print_phase_done("Shell Finder", len(shells_found), elapsed)
            report["7. Shell Finder"] = {"count": len(shells_found), "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("Shell Finder", str(e))
            report["7. Shell Finder"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    elif not domain_targets:
        print_phase_skip("Shell Finder", "no domain targets")
        report["7. Shell Finder"] = {"count": 0, "elapsed": 0, "status": "skipped"}
    else:
        report["7. Shell Finder"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # ══════════════════════════════════════════════════════════
    # PHASE 8: API HUNTER
    # ══════════════════════════════════════════════════════════
    api_findings: List[str] = []
    if not _interrupted and domain_targets:
        print_phase(8, TOTAL_PHASES, "API HUNTER — Secret Key Scanner", "🕵️")
        t0 = time.time()
        try:
            # Load custom paths or use defaults
            if config.hunter_paths_file and os.path.isfile(config.hunter_paths_file):
                paths = read_lines(config.hunter_paths_file)
                paths = [p if p.startswith('/') else '/' + p for p in paths]
            else:
                paths = HUNTER_PATHS

            api_findings = run_api_hunter(
                domain_targets, config.threads, config.timeout,
                paths, config.hunter_bypass, config.hunter_max_bypass,
                config.output_dir
            )
            elapsed = time.time() - t0
            print_phase_done("API Hunter", len(api_findings), elapsed)
            report["8. API Hunter"] = {"count": len(api_findings), "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("API Hunter", str(e))
            report["8. API Hunter"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    elif not domain_targets:
        print_phase_skip("API Hunter", "no domain targets")
        report["8. API Hunter"] = {"count": 0, "elapsed": 0, "status": "skipped"}
    else:
        report["8. API Hunter"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # ══════════════════════════════════════════════════════════
    # PHASE 9: NLA CHECKER (RDP)
    # ══════════════════════════════════════════════════════════
    nla_results: List[str] = []
    if not _interrupted and rdp_targets:
        print_phase(9, TOTAL_PHASES, "NLA CHECKER — RDP Authentication", "🔒")
        t0 = time.time()
        try:
            nla_results = run_nla_checker(
                rdp_targets, config.threads, config.nla_timeout, config.output_dir
            )
            elapsed = time.time() - t0
            print_phase_done("NLA Checker", len(nla_results), elapsed)
            report["9. NLA Checker"] = {"count": len(nla_results), "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("NLA Checker", str(e))
            report["9. NLA Checker"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    else:
        reason = "interrupted" if _interrupted else "no port 3389 in masscan results"
        print_phase_skip("NLA Checker", reason)
        report["9. NLA Checker"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # ══════════════════════════════════════════════════════════
    # PHASE 10: SSH PORT SCAN
    # ══════════════════════════════════════════════════════════
    ssh_open: List[str] = []
    if not _interrupted:
        print_phase(10, TOTAL_PHASES, "SSH PORT SCAN", "📡")
        t0 = time.time()
        try:
            ssh_open = run_ssh_port_scan(
                all_ips, config.threads, config.timeout, config.output_dir
            )
            elapsed = time.time() - t0
            print_phase_done("SSH Port Scan", len(ssh_open), elapsed)
            report["10. SSH Port Scan"] = {"count": len(ssh_open), "elapsed": elapsed, "status": "done"}
        except Exception as e:
            elapsed = time.time() - t0
            print_phase_fail("SSH Port Scan", str(e))
            report["10. SSH Port Scan"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
    else:
        report["10. SSH Port Scan"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # ══════════════════════════════════════════════════════════
    # PHASE 11: SSH CRACKER (optional)
    # ══════════════════════════════════════════════════════════
    ssh_cracked: List[str] = []
    if not _interrupted and ssh_open and config.ssh_users_file and config.ssh_pass_file:
        print_phase(11, TOTAL_PHASES, "SSH CRACKER — Credential Audit", "🔐")
        t0 = time.time()

        sshcracker_bin = detect_sshcracker()
        if sshcracker_bin:
            try:
                # Format targets as IP:22
                ssh_targets = [f"{ip}:22" for ip in ssh_open]
                ssh_cracked = run_ssh_cracker(
                    ssh_targets, config.ssh_users_file, config.ssh_pass_file,
                    config.ssh_threads, config.ssh_timeout,
                    sshcracker_bin, config.output_dir
                )
                elapsed = time.time() - t0
                print_phase_done("SSH Cracker", len(ssh_cracked), elapsed)
                report["11. SSH Cracker"] = {"count": len(ssh_cracked), "elapsed": elapsed, "status": "done"}
            except Exception as e:
                elapsed = time.time() - t0
                print_phase_fail("SSH Cracker", str(e))
                report["11. SSH Cracker"] = {"count": 0, "elapsed": elapsed, "status": "failed"}
        else:
            print_phase_skip("SSH Cracker", "sshcracker binary not found")
            report["11. SSH Cracker"] = {"count": 0, "elapsed": 0, "status": "skipped"}
    else:
        if not ssh_open:
            reason = "no SSH-open hosts found"
        elif not config.ssh_users_file:
            reason = "no SSH credential files provided"
        elif _interrupted:
            reason = "interrupted"
        else:
            reason = "skipped"
        print_phase_skip("SSH Cracker", reason)
        report["11. SSH Cracker"] = {"count": 0, "elapsed": 0, "status": "skipped"}

    # ══════════════════════════════════════════════════════════
    # SAVE COMBINED SUMMARY
    # ══════════════════════════════════════════════════════════
    total_time = time.time() - pipeline_start

    # Write a summary report file
    summary_path = os.path.join(config.output_dir, "SUMMARY.txt")
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("═" * 60 + "\n")
            f.write("  RECON ALL — Pipeline Summary Report\n")
            f.write(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("═" * 60 + "\n\n")

            f.write(f"  Targets File:  {config.targets_file}\n")
            f.write(f"  Ports:         {config.ports}\n")
            f.write(f"  Rate:          {config.rate}\n")
            f.write(f"  Threads:       {config.threads}\n")
            f.write(f"  Total Time:    {total_time:.1f}s ({total_time/60:.1f} min)\n\n")

            f.write("  Phase Results:\n")
            f.write("  " + "-" * 56 + "\n")
            for phase_name, data in report.items():
                count = data.get("count", 0)
                elapsed_p = data.get("elapsed", 0)
                status = data.get("status", "unknown")
                icon = "OK" if status == "done" else ("SKIP" if status == "skipped" else "FAIL")
                f.write(f"  [{icon:4}] {phase_name:<25} {count:>8,} results  {elapsed_p:>8.1f}s\n")

            f.write("\n  Output Files:\n")
            f.write("  " + "-" * 56 + "\n")
            for fname in sorted(os.listdir(config.output_dir)):
                fpath = os.path.join(config.output_dir, fname)
                if os.path.isfile(fpath):
                    size = os.path.getsize(fpath)
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size/1024:.1f} KB"
                    else:
                        size_str = f"{size/(1024*1024):.1f} MB"
                    f.write(f"  📄 {fname:<35} {size_str:>10}\n")

            f.write("\n" + "═" * 60 + "\n")
    except Exception:
        pass

    # Print final report to terminal
    print_final_report(report, config.output_dir, total_time)


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════
def main():
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    print_banner()

    try:
        config = collect_all_inputs()
    except KeyboardInterrupt:
        print("\n  🛑  Input cancelled by user.")
        sys.exit(0)
    except EOFError:
        print("\n  🛑  Input stream closed.")
        sys.exit(0)

    print()
    print("  🚀  Pipeline starting — sit back and relax...")
    print()

    try:
        run_pipeline(config)
    except KeyboardInterrupt:
        print("\n  🛑  Pipeline interrupted. Partial results saved.")
    except Exception as e:
        print(f"\n  ❌  Fatal pipeline error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
