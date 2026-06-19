# ═══════════════════════════════════════════════════════════════
# RECON ALL — Shell Finder Module
# Ported from bot.py (lines 2869-3008)
# ═══════════════════════════════════════════════════════════════
import os
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from utils import (
    build_headers,
    safe_text,
    normalize_host,
    make_session,
    SHELL_PATTERNS,
    ERROR_PATTERNS,
    ThreadSafeCounter,
    ThreadSafeList,
    append_result,
    print_progress,
)


# ═══════════════════════════════════════════════════════════════
# DEFAULT SHELL PATHS
# ═══════════════════════════════════════════════════════════════
DEFAULT_SHELL_PATHS = [
    "wp-content/uploads/",
    "images/",
    "css/",
    "js/",
    "assets/",
    "uploads/",
    "files/",
    "media/",
    "wp-admin/",
    "admin/",
]


def _load_shell_paths(paths_file: Optional[str]) -> List[str]:
    """Load shell paths from file, falling back to defaults."""
    if paths_file and Path(paths_file).exists():
        try:
            with open(paths_file, "r", encoding="utf-8", errors="ignore") as f:
                loaded = [line.strip() for line in f if line.strip()]
            if loaded:
                return loaded
        except Exception:
            pass
    return list(DEFAULT_SHELL_PATHS)


def _check_shell(
    domain: str,
    paths: List[str],
    timeout: int = 15,
    session=None,
) -> Optional[str]:
    """Check a single domain for web shells across all given paths.

    Returns:
        '{category}|{url}' on first match, or None.
    """
    try:
        host = normalize_host(domain)
        if not host:
            return None

        headers = build_headers()
        caller = session or make_session()

        # Pre-flight liveness check: if base URL is dead, skip
        try:
            caller.get(
                f"http://{host}/",
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            try:
                caller.get(
                    f"https://{host}/",
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
            except Exception:
                return None  # Dead host, skip immediately

        for path in paths:
            url = f"http://{host}/{path}"
            try:
                resp = caller.get(url, headers=headers, timeout=timeout, verify=False)
                text = safe_text(resp)

                # Skip known error pages
                if any(err in text for err in ERROR_PATTERNS):
                    continue

                # Check each shell pattern category
                for category in ("shell", "uploader", "mailer", "password"):
                    for pattern in SHELL_PATTERNS[category]:
                        if pattern in text:
                            return f"{category}|{url}"
            except Exception:
                continue

        return None
    except Exception:
        return None


def run_shell_finder(
    domains: List[str],
    threads: int,
    paths_file: str,
    output_dir: str,
) -> List[str]:
    """Scan domains for web shells, uploaders, mailers, and password forms.

    Args:
        domains:    List of raw domain/host strings.
        threads:    Number of concurrent worker threads.
        paths_file: Path to a file containing shell paths (one per line).
                    Falls back to built-in defaults if file missing.
        output_dir: Directory to write result files into.

    Returns:
        List of found shell URLs.
    """
    total = len(domains)
    if total == 0:
        print("  ⚠️  No domains to check.")
        return []

    os.makedirs(output_dir, exist_ok=True)
    paths = _load_shell_paths(paths_file)
    print(f"  📁  Loaded {len(paths)} shell paths")

    results = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    session = make_session(threads)

    # ── Result file paths ──────────────────────────────────────
    all_file = os.path.join(output_dir, "shells_found.txt")
    category_files: Dict[str, str] = {
        "shell": os.path.join(output_dir, "shells_shell.txt"),
        "uploader": os.path.join(output_dir, "shells_uploader.txt"),
        "mailer": os.path.join(output_dir, "shells_mailer.txt"),
        "password": os.path.join(output_dir, "shells_password.txt"),
    }

    def worker(domain: str):
        try:
            res = _check_shell(domain, paths, timeout=15, session=session)
            if res:
                try:
                    category, url = res.split("|", 1)
                except Exception:
                    category, url = "unknown", res

                results.append(url)
                append_result(all_file, url)

                cat_file = category_files.get(
                    category, os.path.join(output_dir, f"shells_{category}.txt")
                )
                append_result(cat_file, url)

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
            suffix = f"Hits:{len(results)} | {speed:.1f} dom/s"
            print_progress(counter.value, total, prefix="Shell Find", suffix=suffix)
            if done_count >= len(futures):
                break
            time.sleep(1.0)

    session.close()

    # ── Final summary ──────────────────────────────────────────
    result_list = results.copy()
    elapsed = time.time() - start_t

    print(f"\n  ✅  Shell Finder complete in {elapsed:.1f}s")
    print(f"      Total hits: {len(result_list):,}")

    return result_list
