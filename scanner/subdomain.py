# ═══════════════════════════════════════════════════════════════
# RECON ALL — Scanner: Subdomain Finder
# Ported from bot.py — 9 passive sources + threaded runner
# ═══════════════════════════════════════════════════════════════
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

from utils import (
    clean_domain,
    DOMAIN_RE,
    make_session,
    ThreadSafeCounter,
    ThreadSafeList,
    append_result,
    print_progress,
    rotate_ua,
)


# ═══════════════════════════════════════════════════════════════
# VALIDATION HELPER
# ═══════════════════════════════════════════════════════════════

def _valid_sub(sub: str, root: str) -> bool:
    """Return True if *sub* is a valid subdomain of *root*."""
    sub = sub.strip().lower().lstrip(".").rstrip(".")
    if not sub or "*" in sub or " " in sub:
        return False
    return sub == root or sub.endswith("." + root)


# ═══════════════════════════════════════════════════════════════
# PASSIVE SOURCES
# ═══════════════════════════════════════════════════════════════

def src_crtsh(domain: str, session) -> Set[str]:
    """crt.sh certificate-transparency search."""
    try:
        r = session.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30,
            headers={"User-Agent": rotate_ua()},
        )
        r.encoding = "utf-8"
        out: Set[str] = set()
        for entry in r.json():
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if _valid_sub(n, domain):
                    out.add(n)
        return out
    except Exception:
        return set()


def src_hackertarget(domain: str, session) -> Set[str]:
    """HackerTarget hostsearch."""
    try:
        r = session.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=20,
        )
        out: Set[str] = set()
        for line in r.text.splitlines():
            sub = line.split(",")[0].strip().lower()
            if _valid_sub(sub, domain):
                out.add(sub)
        return out
    except Exception:
        return set()


def src_alienvault(domain: str, session) -> Set[str]:
    """AlienVault OTX passive DNS."""
    try:
        r = session.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=20,
        )
        data = r.json()
        return {
            rec["hostname"].lower()
            for rec in data.get("passive_dns", [])
            if rec.get("hostname") and _valid_sub(rec["hostname"], domain)
        }
    except Exception:
        return set()


def src_rapiddns(domain: str, session) -> Set[str]:
    """RapidDNS subdomain scraper."""
    try:
        r = session.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=20,
            headers={"User-Agent": rotate_ua()},
        )
        out: Set[str] = set()
        for m in re.findall(
            r'<td>([\w.\-]+\.' + re.escape(domain) + r')</td>',
            r.text,
            re.I,
        ):
            sub = m.strip().lower()
            if _valid_sub(sub, domain):
                out.add(sub)
        return out
    except Exception:
        return set()


def src_certspotter(domain: str, session) -> Set[str]:
    """CertSpotter issuances API."""
    try:
        r = session.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}"
            "&include_subdomains=true&expand=dns_names",
            timeout=20,
        )
        out: Set[str] = set()
        for entry in r.json():
            for n in entry.get("dns_names", []):
                n = n.strip().lower().lstrip("*.")
                if _valid_sub(n, domain):
                    out.add(n)
        return out
    except Exception:
        return set()


def src_anubis(domain: str, session) -> Set[str]:
    """Anubis (jldc.me) subdomain API."""
    try:
        r = session.get(
            f"https://jldc.me/anubis/subdomains/{domain}",
            timeout=15,
        )
        return {
            n.lower()
            for n in r.json()
            if isinstance(n, str) and _valid_sub(n.lower(), domain)
        }
    except Exception:
        return set()


def src_threatminer(domain: str, session) -> Set[str]:
    """ThreatMiner subdomain API."""
    try:
        r = session.get(
            f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
            timeout=20,
        )
        data = r.json()
        return {
            n.lower()
            for n in data.get("results", [])
            if _valid_sub(n.lower(), domain)
        }
    except Exception:
        return set()


def src_urlscan(domain: str, session) -> Set[str]:
    """URLScan.io search API."""
    try:
        r = session.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
            timeout=20,
        )
        out: Set[str] = set()
        for item in r.json().get("results", []):
            host = (item.get("page", {}) or {}).get("domain", "").lower()
            if _valid_sub(host, domain):
                out.add(host)
        return out
    except Exception:
        return set()


def src_wayback(domain: str, session) -> Set[str]:
    """Wayback Machine CDX subdomain extraction."""
    try:
        r = session.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            "&output=json&fl=original&collapse=urlkey",
            timeout=30,
        )
        out: Set[str] = set()
        for row in r.json()[1:]:
            try:
                host = row[0].split("//", 1)[-1].split("/", 1)[0].lower()
                host = host.split(":", 1)[0]
                if _valid_sub(host, domain):
                    out.add(host)
            except Exception:
                continue
        return out
    except Exception:
        return set()


# ═══════════════════════════════════════════════════════════════
# SOURCE REGISTRY — mirrors bot.py PASSIVE_SOURCES
# ═══════════════════════════════════════════════════════════════

PASSIVE_SOURCES = [
    ("crt.sh",       src_crtsh),
    ("HackerTarget", src_hackertarget),
    ("AlienVault",   src_alienvault),
    ("RapidDNS",     src_rapiddns),
    ("CertSpotter",  src_certspotter),
    ("Anubis",       src_anubis),
    ("ThreatMiner",  src_threatminer),
    ("URLScan",      src_urlscan),
    ("Wayback",      src_wayback),
]


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

def run_subdomain_finder(
    domains: List[str],
    threads: int,
    output_dir: str,
) -> List[str]:
    """
    Discover subdomains for one or more root domains using passive sources.

    Parameters
    ----------
    domains : List[str]
        Root domains to enumerate (e.g. ``["example.com"]``).
    threads : int
        Number of concurrent worker threads.
    output_dir : str
        Directory where ``subdomains_all.txt`` will be saved.

    Returns
    -------
    List[str]
        Sorted list of all unique subdomains found.
    """
    if not domains:
        print("  ❌  No domains provided.")
        return []

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "subdomains_all.txt")

    all_subs = ThreadSafeList()
    total_sources = len(PASSIVE_SOURCES) * len(domains)
    completed_sources = ThreadSafeCounter()
    start_t = time.time()

    print(
        f"  🌐  Subdomain Finder started — {len(domains)} domain(s), "
        f"{len(PASSIVE_SOURCES)} sources each"
    )

    def run_source(domain: str, name: str, func):
        """Execute a single passive source for one domain."""
        try:
            with make_session(threads) as session:
                found = func(domain, session)
                for sub in found:
                    if _valid_sub(sub, domain):
                        sub_lower = sub.lower()
                        all_subs.append(sub_lower)
                        append_result(out_file, sub_lower)
        except Exception:
            pass
        finally:
            completed_sources.increment()

    # Run all sources concurrently for each domain
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for domain in domains:
            domain = domain.strip().lower()
            if not domain:
                continue
            for name, func in PASSIVE_SOURCES:
                futures.append(
                    executor.submit(run_source, domain, name, func)
                )

        for future in as_completed(futures):
            print_progress(
                completed_sources.value,
                total_sources,
                prefix="Subdomains",
                suffix=f"| 💎 {len(all_subs):,} found",
            )

    # ── Optional external tools (subfinder, assetfinder, amass) ──
    ext_tasks = [
        (["subfinder", "-d", "{domain}", "-all", "-recursive", "-silent"], "subfinder"),
        (["assetfinder", "--subs-only", "{domain}"], "assetfinder"),
        (["amass", "enum", "-passive", "-d", "{domain}"], "amass"),
    ]
    available_tools = [(cmd, label) for cmd, label in ext_tasks if shutil.which(cmd[0])]

    if available_tools:
        print(f"\n  ⚙️  Running external tools: {', '.join(t[1] for t in available_tools)}")

        def run_external_worker(task, domain):
            cmd_template, label = task
            cmd = [arg.replace("{domain}", domain) for arg in cmd_template]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                for line in proc.stdout.splitlines():
                    sub = line.strip().lower()
                    if _valid_sub(sub, domain):
                        all_subs.append(sub)
                        append_result(out_file, sub)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=len(available_tools)) as ext_executor:
            ext_futures = []
            for domain in domains:
                domain = domain.strip().lower()
                if not domain:
                    continue
                for task in available_tools:
                    ext_futures.append(
                        ext_executor.submit(run_external_worker, task, domain)
                    )
            for f in as_completed(ext_futures):
                pass  # Just wait for completion

    # ── Deduplicate + write final output ──
    unique = sorted({s for s in all_subs.copy() if s})

    try:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("\n".join(unique) + "\n")
    except Exception as e:
        print(f"\n  ⚠️  Failed to write {out_file}: {e}")

    elapsed = time.time() - start_t
    print(f"\n  ✅  Subdomain Finder done — {len(unique):,} unique subdomains in {elapsed:.1f}s")
    return unique
