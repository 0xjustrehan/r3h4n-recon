# ═══════════════════════════════════════════════════════════════
# RECON ALL — Scanner: Domain → IP Resolver
# Ported from bot.py — threaded DNS resolution
# ═══════════════════════════════════════════════════════════════
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from utils import (
    resolve_ip,
    normalize_host,
    ThreadSafeCounter,
    ThreadSafeList,
    make_session,
    append_result,
    print_progress,
)


def run_domain2ip(
    domains: List[str],
    threads: int,
    output_dir: str,
) -> Dict[str, str]:
    """
    Resolve a list of domains to their IP addresses.

    Parameters
    ----------
    domains : List[str]
        Domains (or URLs) to resolve.
    threads : int
        Number of concurrent worker threads.
    output_dir : str
        Directory where ``domain_ips.txt`` will be saved in
        ``domain|IP`` format.

    Returns
    -------
    Dict[str, str]
        Mapping of ``domain → IP`` for successfully resolved domains.
    """
    if not domains:
        print("  ❌  No domains provided.")
        return {}

    total = len(domains)
    print(f"  🌐  Domain→IP started — {total:,} domains, {threads} threads")

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "domain_ips.txt")

    results = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    # We keep a thread-safe dict for the final mapping
    _lock = __import__("threading").Lock()
    domain_ip_map: Dict[str, str] = {}

    def worker(domain: str):
        try:
            host = normalize_host(domain)
            if not host:
                counter.increment()
                return

            ip = resolve_ip(host)
            if ip:
                line = f"{host}|{ip}"
                results.append(line)
                append_result(out_file, line)
                with _lock:
                    domain_ip_map[host] = ip

            counter.increment()
        except Exception:
            counter.increment()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(worker, d): d for d in domains}
        for future in as_completed(futures):
            print_progress(
                counter.value, total,
                prefix="Domain→IP",
                suffix=f"| 💎 {len(results):,} resolved",
            )

    # Write final deduplicated file
    result_lines = results.copy()
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            for line in sorted(set(result_lines)):
                f.write(line + "\n")
    except Exception as e:
        print(f"\n  ⚠️  Failed to write {out_file}: {e}")

    elapsed = time.time() - start_t
    print(f"\n  ✅  Domain→IP done — {len(domain_ip_map):,} resolved in {elapsed:.1f}s")
    return domain_ip_map
