# ═══════════════════════════════════════════════════════════════
# RECON ALL — Web Checker Module
# Ported from bot.py (lines 878-1027, 2454-2546)
# ═══════════════════════════════════════════════════════════════
import os
import re
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from utils import (
    build_headers,
    safe_text,
    normalize_host,
    ThreadSafeCounter,
    ThreadSafeList,
    make_session,
    append_result,
    print_progress,
    BS4_AVAILABLE,
    BeautifulSoup,
    ADMIN_PATHS,
)


# ═══════════════════════════════════════════════════════════════
# CMS DETECTION (ported from bot.py lines 894-947)
# ═══════════════════════════════════════════════════════════════
def detect_cms(
    text: str,
    host: str,
    scheme: str,
    port: Optional[int],
    session: requests.Session,
    headers: Dict[str, str],
    timeout: int,
) -> str:
    """Detect CMS (WordPress, Joomla, Drupal) from page content and probes."""
    cms_list: List[str] = []
    text_lower = text.lower()

    # ── WordPress ──────────────────────────────────────────────
    if "wp-content" in text_lower or "wp-includes" in text_lower:
        cms_list.append("WordPress")
    elif re.search(
        r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress',
        text,
        re.IGNORECASE,
    ):
        cms_list.append("WordPress")
    else:
        try:
            wp_url = f"{scheme}://{host}"
            if port and port not in [80, 443]:
                wp_url += f":{port}"
            wp_url += "/wp-includes/css/buttons.css"
            r = session.get(wp_url, headers=headers, timeout=timeout, verify=False)
            if r.status_code == 200 and "WordPress-style Buttons" in r.text:
                cms_list.append("WordPress")
        except Exception:
            pass

    # ── Joomla ─────────────────────────────────────────────────
    if re.search(
        r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Joomla',
        text,
        re.IGNORECASE,
    ):
        cms_list.append("Joomla")
    elif "/media/system/js/" in text_lower or "/administrator/" in text_lower:
        try:
            j_url = f"{scheme}://{host}"
            if port and port not in [80, 443]:
                j_url += f":{port}"
            j_url += "/administrator/"
            r = session.get(
                j_url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code in [200, 301, 302, 403]:
                cms_list.append("Joomla")
        except Exception:
            pass

    # ── Drupal ─────────────────────────────────────────────────
    if re.search(
        r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Drupal',
        text,
        re.IGNORECASE,
    ):
        cms_list.append("Drupal")
    elif "/sites/default/files/" in text_lower or "/misc/drupal.js" in text_lower:
        cms_list.append("Drupal")
    else:
        try:
            d_url = f"{scheme}://{host}"
            if port and port not in [80, 443]:
                d_url += f":{port}"
            d_url += "/misc/drupal.js"
            r = session.get(d_url, headers=headers, timeout=timeout, verify=False)
            if r.status_code == 200:
                cms_list.append("Drupal")
        except Exception:
            pass

    return ",".join(cms_list) if cms_list else "Unknown"


# ═══════════════════════════════════════════════════════════════
# ADMIN PATH CHECKER (ported from bot.py lines 950-963)
# ═══════════════════════════════════════════════════════════════
def check_admin_paths(
    host: str,
    port: Optional[int],
    scheme: str,
    session: requests.Session,
    headers: Dict[str, str],
    timeout: int = 5,
) -> List[str]:
    """Check common admin paths and return those that respond with 200."""
    found: List[str] = []
    for path in ADMIN_PATHS:
        url = f"{scheme}://{host}"
        if port and port not in [80, 443]:
            url += f":{port}"
        url += path
        try:
            r = session.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code == 200:
                found.append(path)
        except Exception:
            pass
    return found


# ═══════════════════════════════════════════════════════════════
# SINGLE TARGET WEB CHECK (ported from bot.py lines 966-1027)
# ═══════════════════════════════════════════════════════════════
def web_check_target(
    target: str,
    timeout: int = 10,
    session: Optional[requests.Session] = None,
) -> Optional[Dict[str, Any]]:
    """Probe a single target for HTTP(S) liveness, title, server, CMS, admin paths.

    Args:
        target:  IP, IP:Port, or hostname string.
        timeout: HTTP request timeout in seconds.
        session: Optional shared requests.Session for connection pooling.

    Returns:
        A dict with keys: target, status, title, server, cms, admin_paths, redirect.
        Returns None if the target is unreachable on all schemes.
    """
    line = target.strip()
    if not line:
        return None

    host = line
    port: Optional[int] = None
    if ":" in line:
        parts = line.rsplit(":", 1)
        if parts[1].isdigit():
            host, port = parts[0], int(parts[1])

    result: Dict[str, Any] = {
        "target": target,
        "status": None,
        "title": "",
        "server": "",
        "cms": "",
        "admin_paths": [],
        "redirect": "",
    }

    headers = build_headers()
    session = session or requests.Session()
    session.verify = False

    # Determine schemes based on port
    if port:
        if port in [80, 8080, 8000, 8888]:
            schemes = ["http"]
        elif port in [443, 8443]:
            schemes = ["https"]
        else:
            schemes = ["http", "https"]
    else:
        schemes = ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{host}"
        if port and port not in [80, 443]:
            url += f":{port}"
        try:
            resp = session.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            result["status"] = resp.status_code
            result["server"] = resp.headers.get("Server", "")

            if resp.url != url:
                result["redirect"] = resp.url

            text = safe_text(resp)

            # Extract title
            m = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
            if m:
                result["title"] = re.sub(r'<[^>]+>', '', m.group(1)).strip()[:100]

            # Detect CMS
            result["cms"] = detect_cms(text, host, scheme, port, session, headers, timeout)

            # Check admin paths (only for certain status codes)
            if result["status"] in [200, 301, 302, 401, 403]:
                result["admin_paths"] = check_admin_paths(
                    host, port, scheme, session, headers, timeout=5
                )

            return result
        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
# MAIN RUNNER (ported from bot.py lines 2454-2546)
# ═══════════════════════════════════════════════════════════════
def run_web_checker(
    targets: List[str],
    threads: int,
    timeout: int,
    output_dir: str,
) -> List[str]:
    """Run the web checker against a list of targets using a thread pool.

    Args:
        targets:    List of target strings (IP, IP:Port, hostname).
        threads:    Number of concurrent worker threads.
        timeout:    HTTP request timeout in seconds.
        output_dir: Directory where results are saved.

    Returns:
        A list of live target strings that responded to HTTP(S) probes.
    """
    total = len(targets)
    if total == 0:
        print("  ❌  No targets provided.")
        return []

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "web_live.txt")

    print(f"  🌐  Web Checker started — {total:,} targets, {threads} threads, {timeout}s timeout")

    live_results = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    # Shared session with connection pooling
    session = make_session(threads=threads)

    def worker(target: str):
        try:
            res = web_check_target(target, timeout, session=session)
            if res:
                line = res["target"]

                # Build a rich detail string for terminal display
                parts = [line]
                if res.get("status"):
                    parts.append(f"[{res['status']}]")
                if res.get("title"):
                    parts.append(f"T:{res['title'][:40]}")
                if res.get("server"):
                    parts.append(f"S:{res['server']}")
                if res.get("cms") and res["cms"] != "Unknown":
                    parts.append(f"CMS:{res['cms']}")
                if res.get("admin_paths"):
                    parts.append(f"Admin:{','.join(res['admin_paths'])}")

                detail_line = " | ".join(parts)
                live_results.append(line)
                append_result(out_file, detail_line)
        except Exception:
            pass
        finally:
            counter.increment()

    # Submit all tasks to the thread pool
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, t) for t in targets]

        # Progress monitoring loop
        try:
            while counter.value < total:
                time.sleep(1.0)
                now = time.time()
                elapsed = now - start_t
                done_count = counter.value
                speed = done_count / elapsed if elapsed > 0 else 0

                print_progress(
                    done_count,
                    total,
                    prefix="🌐 Web",
                    suffix=f"💎 {len(live_results):,} live  ⚡ {speed:.1f}/s",
                )
        except KeyboardInterrupt:
            print("\n\n  🛑  Ctrl+C — stopping web checker...")
            executor.shutdown(wait=False, cancel_futures=True)

    # Final progress update
    print_progress(
        total,
        total,
        prefix="🌐 Web",
        suffix=f"💎 {len(live_results):,} live",
    )

    session.close()

    result_lines = live_results.copy()

    if result_lines:
        print(f"  ✅  Web Checker complete — {len(result_lines):,} live targets")
        print(f"  📁  Results saved to: {out_file}")
    else:
        print("  ❌  No live targets found.")

    return result_lines


# ═══════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Web checker — port from recon bot")
    parser.add_argument("targets_file", help="Path to targets file (one target per line)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Thread count (default: 50)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")

    args = parser.parse_args()

    with open(args.targets_file, "r") as f:
        target_list = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    results = run_web_checker(target_list, args.threads, args.timeout, args.output)
    print(f"\nTotal live: {len(results)}")
