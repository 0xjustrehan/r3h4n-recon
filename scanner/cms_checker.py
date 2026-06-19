# ═══════════════════════════════════════════════════════════════
# RECON ALL — CMS Checker Module
# Ported from bot.py (lines 3109-3270)
# ═══════════════════════════════════════════════════════════════
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from utils import (
    build_headers,
    safe_text,
    normalize_host,
    make_session,
    ThreadSafeCounter,
    ThreadSafeList,
    append_result,
    print_progress,
)


def run_cms_checker(domains: List[str], threads: int, output_dir: str) -> Dict[str, List[str]]:
    """Check each domain for WordPress, Joomla, or Drupal CMS.

    Args:
        domains:    List of raw domain/host strings.
        threads:    Number of concurrent worker threads.
        output_dir: Directory to write result files into.

    Returns:
        Dict with keys 'wordpress', 'joomla', 'drupal', 'other'
        mapping to lists of detected hosts.
    """
    total = len(domains)
    if total == 0:
        print("  ⚠️  No domains to check.")
        return {"wordpress": [], "joomla": [], "drupal": [], "other": []}

    os.makedirs(output_dir, exist_ok=True)

    wp_results = ThreadSafeList()
    joomla_results = ThreadSafeList()
    drupal_results = ThreadSafeList()
    other_results = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    session = make_session(threads)

    # ── Result file paths ──────────────────────────────────────
    wp_file = os.path.join(output_dir, "cms_wordpress.txt")
    joomla_file = os.path.join(output_dir, "cms_joomla.txt")
    drupal_file = os.path.join(output_dir, "cms_drupal.txt")
    other_file = os.path.join(output_dir, "cms_other.txt")
    all_file = os.path.join(output_dir, "cms_all.txt")

    def worker(domain: str):
        try:
            host = normalize_host(domain)
            if not host:
                counter.increment()
                return

            headers = build_headers()
            cms = None

            # Pre-flight liveness check
            try:
                session.get(f"http://{host}/", headers=headers, timeout=10, allow_redirects=True)
            except Exception:
                try:
                    session.get(f"https://{host}/", headers=headers, timeout=10, allow_redirects=True)
                except Exception:
                    counter.increment()
                    return  # Host is dead, skip

            # ── WordPress check ────────────────────────────────
            for url in [
                f"http://{host}/wp-includes/css/buttons.css",
                f"https://{host}/wp-includes/css/buttons.css",
                f"http://{host}/",
                f"https://{host}/",
            ]:
                try:
                    resp = session.get(url, headers=headers, timeout=10, allow_redirects=True)
                    text = safe_text(resp)
                    if "WordPress-style Buttons" in text or "wp-" in text.lower():
                        cms = "WordPress"
                        break
                except Exception:
                    continue

            # ── Joomla check ───────────────────────────────────
            if not cms:
                for url in [
                    f"http://{host}/administrator/",
                    f"https://{host}/administrator/",
                ]:
                    try:
                        resp = session.get(url, headers=headers, timeout=10, allow_redirects=False)
                        text = safe_text(resp)
                        if resp.status_code in [200, 301, 302, 403] or "Joomla" in text:
                            cms = "Joomla"
                            break
                    except Exception:
                        continue

            # ── Drupal check ───────────────────────────────────
            if not cms:
                for url in [
                    f"http://{host}/misc/drupal.js",
                    f"https://{host}/misc/drupal.js",
                ]:
                    try:
                        resp = session.get(url, headers=headers, timeout=10)
                        if resp.status_code == 200:
                            cms = "Drupal"
                            break
                    except Exception:
                        continue

            # ── Store results by CMS type ──────────────────────
            if cms == "WordPress":
                wp_results.append(host)
                append_result(wp_file, host)
                append_result(all_file, f"[WordPress] {host}")
            elif cms == "Joomla":
                joomla_results.append(host)
                append_result(joomla_file, host)
                append_result(all_file, f"[Joomla] {host}")
            elif cms == "Drupal":
                drupal_results.append(host)
                append_result(drupal_file, host)
                append_result(all_file, f"[Drupal] {host}")
            else:
                other_results.append(host)
                append_result(other_file, host)
                append_result(all_file, f"[Other] {host}")

            counter.increment()
        except Exception:
            counter.increment()

    # ── Execute workers ────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, d) for d in domains]

        # Progress reporting loop
        while True:
            done_count = sum(1 for f in futures if f.done())
            elapsed = time.time() - start_t
            speed = counter.value / elapsed if elapsed > 0 else 0
            suffix = (
                f"WP:{len(wp_results)} J:{len(joomla_results)} "
                f"D:{len(drupal_results)} | {speed:.1f} dom/s"
            )
            print_progress(counter.value, total, prefix="CMS Check", suffix=suffix)
            if done_count >= len(futures):
                break
            time.sleep(1.0)

    session.close()

    # ── Final summary ──────────────────────────────────────────
    wp_list = wp_results.copy()
    joomla_list = joomla_results.copy()
    drupal_list = drupal_results.copy()
    other_list = other_results.copy()
    elapsed = time.time() - start_t

    print(f"\n  ✅  CMS Check complete in {elapsed:.1f}s")
    print(f"      WordPress : {len(wp_list):,}")
    print(f"      Joomla    : {len(joomla_list):,}")
    print(f"      Drupal    : {len(drupal_list):,}")
    print(f"      Other     : {len(other_list):,}")

    return {
        "wordpress": wp_list,
        "joomla": joomla_list,
        "drupal": drupal_list,
        "other": other_list,
    }
