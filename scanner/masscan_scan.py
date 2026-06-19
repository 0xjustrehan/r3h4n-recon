# ═══════════════════════════════════════════════════════════════
# RECON ALL — Masscan Scanner Module
# Ported from bot.py (lines 2129-2320)
# ═══════════════════════════════════════════════════════════════
import os
import re
import sys
import time
import signal
import tempfile
import subprocess
from typing import List


def _temp_path(suffix: str = ".txt") -> str:
    """Create a temporary file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def count_ips_in_targets(targets_file: str) -> int:
    """Count the total number of IPs/CIDRs in a targets file.

    For CIDR ranges like /24, estimates the IP count.
    For plain IPs, counts 1 each.
    """
    total = 0
    try:
        with open(targets_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "/" in line:
                    # CIDR — estimate count
                    try:
                        prefix = int(line.split("/")[1])
                        total += 2 ** (32 - prefix)
                    except (ValueError, IndexError):
                        total += 1
                else:
                    total += 1
    except Exception:
        total = 0
    return total


def run_masscan(
    targets_file: str,
    ports: str,
    rate: str,
    masscan_bin: str,
    output_dir: str,
) -> List[str]:
    """Run masscan against a targets file and return a list of IP:Port strings.

    Args:
        targets_file: Path to a file containing target IPs/CIDRs (one per line).
        ports:        Port specification string (e.g. "80", "80,443", "0-65535").
        rate:         Packet rate string (e.g. "10000").
        masscan_bin:  Absolute path to the masscan binary.
        output_dir:   Directory where final results are saved.

    Returns:
        A list of "IP:Port" strings for every open port found.
    """

    if not os.path.isfile(masscan_bin):
        print(f"  ❌  masscan binary not found at: {masscan_bin}")
        return []

    if not os.path.isfile(targets_file):
        print(f"  ❌  Targets file not found: {targets_file}")
        return []

    os.makedirs(output_dir, exist_ok=True)

    # Create temp files for masscan I/O
    in_p = _temp_path(suffix=".txt")
    out_p = _temp_path(suffix=".grep")

    proc = None
    results: List[str] = []

    try:
        # Copy targets into the temp input file (masscan needs its own copy)
        with open(targets_file, "r", encoding="utf-8", errors="ignore") as src, \
             open(in_p, "w", encoding="utf-8") as dst:
            for line in src:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    dst.write(stripped + "\n")

        total_ips = count_ips_in_targets(in_p)

        cmd = [
            masscan_bin,
            "-p", str(ports),
            "--includefile", in_p,
            "--rate", str(rate),
            "-oG", out_p,
            "--open",
            "--exclude", "255.255.255.255",
        ]

        print(f"  🔍  Launching masscan  ports={ports}  rate={rate}  targets≈{total_ips:,}")
        print(f"  ⌨️   Press Ctrl+C to stop early (partial results will be saved)\n")

        # Launch the masscan process
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,
        )

        start_time = time.time()
        hits = 0
        last_update = 0.0

        # Monitor stderr for progress updates
        try:
            for line in proc.stderr:
                line = line.strip()
                now = time.time()

                if ("done" in line or "found=" in line) and (now - last_update) > 3:
                    pct_m = re.search(r'(\d+\.?\d*)\s*%', line)
                    pct = float(pct_m.group(1)) if pct_m else 0.0

                    found_m = re.search(r'found\s*=\s*(\d+)', line)
                    hits = int(found_m.group(1)) if found_m else hits

                    elapsed = now - start_time
                    scanned_ips = int(total_ips * (pct / 100)) if total_ips else 0
                    ips_per_sec = scanned_ips / elapsed if elapsed > 0 else 0
                    kbps = (ips_per_sec * 60 * 8) / 1000

                    # ETA calculation
                    if pct > 0 and elapsed > 0:
                        eta_sec = (elapsed / (pct / 100)) - elapsed
                        eta_str = time.strftime("%H:%M:%S", time.gmtime(int(eta_sec)))
                    else:
                        eta_str = "…"

                    elapsed_str = time.strftime("%H:%M:%S", time.gmtime(int(elapsed)))
                    bar_len = int(30 * (pct / 100))
                    bar = "█" * bar_len + "░" * (30 - bar_len)

                    sys.stdout.write(
                        f"\r  [{bar}] {pct:.1f}%  "
                        f"⚡ {kbps/1000:.1f}Mbps  "
                        f"📡 {scanned_ips:,}/{total_ips:,}  "
                        f"✅ Hits:{hits:,}  "
                        f"⏱ {elapsed_str}  ⏳ ETA:{eta_str}"
                    )
                    sys.stdout.flush()
                    last_update = now

        except KeyboardInterrupt:
            print("\n\n  🛑  Ctrl+C detected — stopping masscan...")
            # Kill the subprocess gracefully
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

        # Wait for process to finish (if still running)
        if proc and proc.poll() is None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        print()  # newline after progress bar

        # Parse the grep output file
        if os.path.exists(out_p):
            with open(out_p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = re.search(r'Host:\s+([\d.]+).*?Ports:\s+(\d+)/open', line)
                    if m:
                        results.append(f"{m.group(1)}:{m.group(2)}")

        # Save results to output directory
        out_file = os.path.join(output_dir, "masscan_results.txt")
        if results:
            with open(out_file, "w", encoding="utf-8") as f:
                for r in results:
                    f.write(r + "\n")
            print(f"  ✅  Masscan complete — {len(results):,} open ports found")
            print(f"  📁  Results saved to: {out_file}")
        else:
            print("  ❌  No open ports found.")

    except Exception as e:
        print(f"\n  ❌  Masscan error: {e}")

    finally:
        # Clean up the subprocess
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        # Clean up temp files
        for p in [in_p, out_p]:
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass

    return results


# ═══════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Masscan wrapper — port from recon bot")
    parser.add_argument("targets", help="Path to targets file (IPs/CIDRs, one per line)")
    parser.add_argument("-p", "--ports", default="80,443", help="Ports to scan (default: 80,443)")
    parser.add_argument("-r", "--rate", default="10000", help="Packet rate (default: 10000)")
    parser.add_argument("-b", "--bin", default="masscan", help="Path to masscan binary")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")

    args = parser.parse_args()
    results = run_masscan(args.targets, args.ports, args.rate, args.bin, args.output)
    print(f"\nTotal results: {len(results)}")
