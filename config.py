# ═══════════════════════════════════════════════════════════════
# RECON ALL — Configuration & Input Collection
# ═══════════════════════════════════════════════════════════════
import os
import sys
import shutil
import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class PipelineConfig:
    """Holds all pipeline configuration collected upfront."""
    # ── Masscan ──
    targets_file: str = ""
    ports: str = "80,443"
    rate: str = "10000"
    masscan_bin: str = ""

    # ── Global ──
    threads: int = 100
    timeout: int = 10
    output_dir: str = ""

    # ── Reverse IP ──
    api_keys: Dict[str, str] = field(default_factory=dict)

    # ── API Hunter ──
    hunter_paths_file: str = ""
    hunter_bypass: bool = True
    hunter_max_bypass: int = 40

    # ── Shell Finder ──
    shell_paths_file: str = ""

    # ── SSH ──
    ssh_users_file: str = ""
    ssh_pass_file: str = ""
    ssh_threads: int = 50
    ssh_timeout: int = 5

    # ── NLA ──
    nla_timeout: int = 10

    # ── Flags ──
    is_windows: bool = False


def detect_masscan() -> str:
    """Auto-detect masscan binary for current platform."""
    system = platform.system().lower()

    if system == "windows":
        # Check common Windows locations
        candidates = [
            shutil.which("masscan"),
            shutil.which("masscan.exe"),
            os.path.join(os.getcwd(), "masscan.exe"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "masscan.exe"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "masscan.exe"),
            r"C:\masscan\masscan.exe",
            r"C:\tools\masscan.exe",
            r"C:\Program Files\masscan\masscan.exe",
        ]
    else:
        candidates = [
            shutil.which("masscan"),
            "/usr/bin/masscan",
            "/usr/local/bin/masscan",
            os.path.join(os.getcwd(), "masscan"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "masscan"),
        ]

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return ""


def detect_sshcracker() -> str:
    """Auto-detect sshcracker binary."""
    system = platform.system().lower()
    if system == "windows":
        candidates = [
            shutil.which("sshcracker"),
            shutil.which("sshcracker.exe"),
            os.path.join(os.getcwd(), "sshcracker.exe"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "sshcracker.exe"),
        ]
    else:
        candidates = [
            shutil.which("sshcracker"),
            "./sshcracker",
            os.path.join(os.getcwd(), "sshcracker"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "sshcracker"),
        ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return ""


def _ask(prompt: str, default: str = "", required: bool = False) -> str:
    """Ask user for input with optional default."""
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"  {prompt}{suffix}: ").strip()
        if not val and default:
            return default
        if not val and required:
            print("  ⚠️  This field is required.")
            continue
        if val:
            return val
        if not required:
            return ""


def _ask_file(prompt: str, required: bool = False) -> str:
    """Ask user for a file path, validate it exists."""
    while True:
        val = _ask(prompt, required=required)
        if not val and not required:
            return ""
        if val and os.path.isfile(val):
            return os.path.abspath(val)
        if val:
            print(f"  ⚠️  File not found: {val}")
        if not required:
            return ""


def _ask_yesno(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question."""
    suffix = " [Y/n]" if default else " [y/N]"
    val = input(f"  {prompt}{suffix}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "1", "true")


def collect_all_inputs() -> PipelineConfig:
    """Interactively collect ALL pipeline inputs upfront."""
    config = PipelineConfig()
    config.is_windows = platform.system().lower() == "windows"

    print()
    print("  ╔════════════════════════════════════════════════════╗")
    print("  ║        📋  COLLECTING ALL INPUTS UPFRONT          ║")
    print("  ╚════════════════════════════════════════════════════╝")
    print()

    # ── Phase 1: Masscan ──
    print("  ── 🔍 MASSCAN CONFIGURATION ──")
    config.targets_file = _ask_file("Targets file (IPs/CIDRs)", required=True)
    config.ports = _ask("Ports to scan (e.g., 80,443 or 80-443)", default="80,443")
    config.rate = _ask("Scan rate (packets/sec)", default="10000")

    # Auto-detect masscan
    config.masscan_bin = detect_masscan()
    if config.masscan_bin:
        print(f"  ✅  Masscan found: {config.masscan_bin}")
    else:
        masscan_path = _ask("Masscan binary path (not found automatically)")
        if masscan_path and os.path.isfile(masscan_path):
            config.masscan_bin = masscan_path
        else:
            print("  ⚠️  Masscan not found — Phase 1 will be skipped.")
            print("      Provide a file with pre-scanned IP:Port results instead?")
            prescan = _ask_file("Pre-scanned results file (IP:Port per line, optional)")
            if prescan:
                config.targets_file = prescan
                config.masscan_bin = "__prescan__"

    print()

    # ── Global ──
    print("  ── ⚙️  GLOBAL SETTINGS ──")
    threads_str = _ask("Global thread count", default="100")
    config.threads = int(threads_str) if threads_str.isdigit() else 100
    timeout_str = _ask("Global HTTP timeout (seconds)", default="10")
    config.timeout = int(timeout_str) if timeout_str.isdigit() else 10
    print()

    # ── Phase 3: Reverse IP ──
    print("  ── 🌐 REVERSE IP (Optional API Keys) ──")
    print("  Format: provider:KEY (e.g., shodan:abc123)")
    print("  Supported: shodan, securitytrails, chaos, xreverselabs")
    keys_input = _ask("API keys (space-separated, or 'skip')", default="skip")
    if keys_input.lower() != "skip":
        for part in keys_input.split():
            if ":" in part:
                k, v = part.split(":", 1)
                config.api_keys[k.lower().strip()] = v.strip()
    print()

    # ── Phase 8: API Hunter ──
    print("  ── 🕵️  API HUNTER CONFIGURATION ──")
    config.hunter_paths_file = _ask_file("Custom paths file (optional, or Enter for defaults)")
    config.hunter_bypass = _ask_yesno("Enable 403 bypass?", default=True)
    if config.hunter_bypass:
        mb_str = _ask("Max bypass attempts per URL", default="40")
        config.hunter_max_bypass = int(mb_str) if mb_str.isdigit() else 40
    print()

    # ── Phase 7: Shell Finder ──
    print("  ── 🐚 SHELL FINDER CONFIGURATION ──")
    config.shell_paths_file = _ask_file("Custom shell paths file (optional, or Enter for defaults)")
    print()

    # ── Phase 9: NLA Checker ──
    print("  ── 🔒 NLA CHECKER CONFIGURATION ──")
    nla_str = _ask("NLA timeout (seconds)", default="10")
    config.nla_timeout = int(nla_str) if nla_str.isdigit() else 10
    print()

    # ── Phase 10-11: SSH ──
    print("  ── 🔐 SSH CONFIGURATION ──")
    config.ssh_users_file = _ask_file("SSH users file (optional, for SSH Cracker)")
    if config.ssh_users_file:
        config.ssh_pass_file = _ask_file("SSH passwords file", required=True)
        st_str = _ask("SSH Cracker threads", default="50")
        config.ssh_threads = int(st_str) if st_str.isdigit() else 50
        sto_str = _ask("SSH Cracker timeout (seconds)", default="5")
        config.ssh_timeout = int(sto_str) if sto_str.isdigit() else 5
    print()

    # ── Output directory ──
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    config.output_dir = os.path.join(base_dir, f"scan_{timestamp}")
    os.makedirs(config.output_dir, exist_ok=True)

    # ── Summary ──
    print("  ╔════════════════════════════════════════════════════╗")
    print("  ║              ✅  INPUT COLLECTION DONE             ║")
    print("  ╚════════════════════════════════════════════════════╝")
    print()
    print(f"  📁  Targets:     {config.targets_file}")
    print(f"  🔌  Ports:       {config.ports}")
    print(f"  ⚡  Rate:        {config.rate}")
    print(f"  🧵  Threads:     {config.threads}")
    print(f"  ⏱️   Timeout:     {config.timeout}s")
    print(f"  🔑  API Keys:    {len(config.api_keys)} configured")
    print(f"  🛡️   403 Bypass:  {'Yes' if config.hunter_bypass else 'No'}")
    print(f"  🔐  SSH Cracker: {'Yes' if config.ssh_users_file else 'Skipped'}")
    print(f"  📁  Output:      {config.output_dir}")
    print()

    return config
