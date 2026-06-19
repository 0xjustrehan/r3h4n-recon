# ═══════════════════════════════════════════════════════════════
# RECON ALL — RDP NLA Checker Module
# Ported from bot.py (lines 1743-1850)
# ═══════════════════════════════════════════════════════════════
import os
import sys
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from utils import (
    ThreadSafeCounter,
    ThreadSafeList,
    append_result,
    print_progress,
    strip_port,
)


# ═══════════════════════════════════════════════════════════════
# RDP NLA CHECK (ported from bot.py lines 1743-1763)
# ═══════════════════════════════════════════════════════════════
# X.224 Connection Request with RDP Negotiation Request (TYPE_RDP_NEG_REQ)
# requesting CredSSP (NLA) — protocol flags 0x03 = PROTOCOL_SSL | PROTOCOL_HYBRID
RDP_NEG_REQ = (
    b'\x03\x00\x00\x13'   # TPKT header: version=3, length=19
    b'\x0e\xe0'            # X.224 CR: length=14, type=0xE0 (Connection Request)
    b'\x00\x00\x00\x00\x00'  # dst-ref, src-ref, class
    b'\x01'                # RDP Negotiation Request type
    b'\x00'                # flags
    b'\x08\x00'            # length=8
    b'\x03\x00\x00\x00'   # requestedProtocols = PROTOCOL_SSL | PROTOCOL_HYBRID
)


def check_rdp_nla(host: str, port: int = 3389, timeout: int = 10) -> str:
    """Check whether an RDP server requires NLA (Network Level Authentication).

    Sends an X.224 Connection Request with NLA negotiation and inspects the
    response bytes at offset 11-14 for protocol flags.

    Returns:
        "NLA"     — server requires NLA (CredSSP / PROTOCOL_HYBRID)
        "NON_NLA" — server does NOT require NLA
        "ERR"     — connection or protocol error
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.send(RDP_NEG_REQ)
        data = s.recv(1024)
        if len(data) < 11:
            return "NON_NLA"
        # Bytes 11-14 contain the selectedProtocol field in the Negotiation Response.
        # 0x02 = PROTOCOL_HYBRID (NLA), 0x03 = PROTOCOL_HYBRID_EX
        if b'\x02' in data[11:15] or b'\x03' in data[11:15]:
            return "NLA"
        return "NON_NLA"
    except Exception:
        return "ERR"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# MAIN RUNNER (ported from bot.py lines 1766-1849)
# ═══════════════════════════════════════════════════════════════
def run_nla_checker(
    targets: List[str],
    threads: int,
    timeout: int,
    output_dir: str,
) -> List[str]:
    """Run the NLA checker against a list of IP:Port targets.

    Args:
        targets:    List of "IP:Port" strings (port should be 3389).
        threads:    Number of concurrent worker threads.
        timeout:    Socket timeout in seconds.
        output_dir: Directory where results are saved.

    Returns:
        A list of target strings where NLA is enabled.
    """
    # Filter out blanks and comments
    lines = [l.strip() for l in targets if l.strip() and not l.strip().startswith("#")]
    total = len(lines)

    if total == 0:
        print("  ❌  No valid targets provided.")
        return []

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "nla_results.txt")

    print(f"  🔄  NLA Checker started — {total:,} targets, {threads} threads, {timeout}s timeout")

    nla_enabled = ThreadSafeList()
    nla_disabled = ThreadSafeList()
    nla_errors = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    def worker(line: str):
        try:
            if ":" in line:
                h, p = line.split(":", 1)
            else:
                h, p = line, 3389

            status = check_rdp_nla(h, int(p), timeout)

            if status == "NLA":
                nla_enabled.append(line)
                append_result(out_file, f"[NLA]     {line}")
            elif status == "NON_NLA":
                nla_disabled.append(line)
                append_result(out_file, f"[NON_NLA] {line}")
            else:
                nla_errors.append(line)
                append_result(out_file, f"[ERR]     {line}")
        except Exception:
            nla_errors.append(line)
        finally:
            counter.increment()

    # Submit all tasks to the thread pool
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, line) for line in lines]

        # Progress monitoring loop
        try:
            while counter.value < total:
                time.sleep(1.0)
                now = time.time()
                elapsed = now - start_t
                done_count = counter.value
                speed = done_count / elapsed if elapsed > 0 else 0
                eta = (total - done_count) / speed if speed > 0 else 0

                print_progress(
                    done_count,
                    total,
                    prefix="🔄 NLA",
                    suffix=(
                        f"💎 NLA:{len(nla_enabled):,}  "
                        f"⚡ {speed:.1f}/s  "
                        f"⏳ ~{int(eta)}s"
                    ),
                )
        except KeyboardInterrupt:
            print("\n\n  🛑  Ctrl+C — stopping NLA checker...")
            executor.shutdown(wait=False, cancel_futures=True)

    # Final progress update
    print_progress(
        total,
        total,
        prefix="🔄 NLA",
        suffix=f"💎 NLA:{len(nla_enabled):,}",
    )

    results = nla_enabled.copy()

    # Print summary
    print(f"  ✅  NLA Checker complete")
    print(f"      NLA enabled:  {len(nla_enabled):,}")
    print(f"      NLA disabled: {len(nla_disabled):,}")
    print(f"      Errors:       {len(nla_errors):,}")
    print(f"  📁  Results saved to: {out_file}")

    return results


# ═══════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RDP NLA checker — port from recon bot")
    parser.add_argument("targets_file", help="Path to targets file (IP:Port, one per line)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Thread count (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="Socket timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")

    args = parser.parse_args()

    with open(args.targets_file, "r") as f:
        target_list = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    results = run_nla_checker(target_list, args.threads, args.timeout, args.output)
    print(f"\nTotal NLA enabled: {len(results)}")
