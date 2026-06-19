# ═══════════════════════════════════════════════════════════════
# RECON ALL — Scanner: Reverse IP  (IP → Domains)
# Ported from bot.py — all API sources + threaded runner
# ═══════════════════════════════════════════════════════════════
import os
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set

from utils import (
    build_headers,
    safe_text,
    safe_request,
    clean_domain,
    resolve_ip,
    DOMAIN_RE,
    make_session,
    ThreadSafeCounter,
    ThreadSafeList,
    append_result,
    print_progress,
)


# ═══════════════════════════════════════════════════════════════
# API SOURCES (free / no key required)
# ═══════════════════════════════════════════════════════════════

def api_rapiddns(ip: str, session) -> Set[str]:
    """RapidDNS reverse-IP lookup."""
    try:
        url = f"https://rapiddns.io/s/{ip}?full=1&down=1"
        resp = safe_request(session, url, timeout=20)
        text = safe_text(resp)
        matches = re.findall(
            r'<td>(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z]{1,63}</td>',
            text,
        )
        domains: Set[str] = set()
        for m in matches:
            d = m.replace("<td>", "").replace("</td>", "").lower()
            if not any(
                d.startswith(x)
                for x in [
                    "webmail.", "ftp.", "cpanel.", "webdisk.",
                    "cpcalendars.", "cpcontacts.", "mail.", "ns1.", "ns2.",
                ]
            ):
                domains.add(clean_domain(d.replace("www.", "")))
        return domains
    except Exception:
        return set()


def api_webscan(ip: str, session) -> Set[str]:
    """Webscan.cc reverse-IP lookup."""
    try:
        url = f"https://api.webscan.cc/?action=query&ip={ip}"
        resp = safe_request(session, url, timeout=15)
        text = safe_text(resp)
        matches = re.findall(r'"domain": "(.*?)",', text)
        return {clean_domain(d.replace("www.", "")) for d in matches}
    except Exception:
        return set()


def api_xreverselabs(ip: str, session, apikey: str = "unknown") -> Set[str]:
    """xReverseLabs reverse-IP lookup."""
    try:
        url = (
            f"http://de-datacenter.xreverselabs.my.id:1337/reverse-ip"
            f"?apikey={apikey}&ip={ip}"
        )
        resp = safe_request(session, url, timeout=15)
        text = safe_text(resp)
        matches = re.findall(r'"(.*?)"', text)
        return {
            clean_domain(d.replace("www.", ""))
            for d in matches
            if d not in ("status", "success", "domains", "unknown")
        }
    except Exception:
        return set()


def api_hackertarget(ip: str, session) -> Set[str]:
    """HackerTarget reverse-IP lookup."""
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = safe_request(session, url, timeout=10)
        text = safe_text(resp)
        if "error" in text.lower() or "No records" in text:
            return set()
        return {
            clean_domain(line.strip())
            for line in text.splitlines()
            if line.strip() and not line.startswith(("Error", "API", "No "))
        }
    except Exception:
        return set()


def api_viewdns(ip: str, session) -> Set[str]:
    """ViewDNS.info reverse-IP lookup."""
    try:
        url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
        resp = safe_request(
            session, url,
            headers=build_headers(referer="https://viewdns.info/"),
            timeout=15,
        )
        text = safe_text(resp)
        matches = re.findall(
            r'<td[^>]*>([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})</td>',
            text,
        )
        return {clean_domain(m) for m in matches}
    except Exception:
        return set()


def api_ipinfo(ip: str, session) -> Set[str]:
    """IPinfo reverse-IP lookup (hostname field)."""
    try:
        resp = safe_request(session, f"https://ipinfo.io/{ip}/json", timeout=10)
        data = json.loads(safe_text(resp))
        if isinstance(data, dict) and data.get("hostname"):
            return {clean_domain(data["hostname"])}
        return set()
    except Exception:
        return set()


def api_yougetsignal(ip: str, session) -> Set[str]:
    """YouGetSignal reverse-IP lookup."""
    try:
        resp = safe_request(
            session,
            "https://domains.yougetsignal.com/domains.php",
            data={"remoteAddress": ip, "key": ""},
            method="POST",
            timeout=12,
        )
        result = json.loads(safe_text(resp))
        domains: Set[str] = set()
        if isinstance(result, dict):
            for pair in result.get("domainArray", []):
                if pair and isinstance(pair, (list, tuple)) and pair:
                    domains.add(clean_domain(pair[0]))
        return domains
    except Exception:
        return set()


def api_dnslytics(ip: str, session) -> Set[str]:
    """DNSlytics reverse-IP lookup."""
    try:
        resp = safe_request(
            session,
            f"https://dnslytics.com/api/v1/reverseip/{ip}",
            timeout=12,
        )
        data = json.loads(safe_text(resp))
        domains: Set[str] = set()
        if isinstance(data, dict):
            for d in data.get("domains", []):
                if isinstance(d, str):
                    domains.add(clean_domain(d))
                elif isinstance(d, dict) and d.get("domain"):
                    domains.add(clean_domain(d["domain"]))
        return domains
    except Exception:
        return set()


def api_reverseip(ip: str, session) -> Set[str]:
    """reverse-ip.info API lookup."""
    try:
        resp = safe_request(
            session,
            f"https://reverse-ip.info/api/v1/{ip}",
            timeout=10,
        )
        data = json.loads(safe_text(resp))
        if isinstance(data, list):
            return {clean_domain(d) for d in data if isinstance(d, str)}
        if isinstance(data, dict):
            return {
                clean_domain(d)
                for d in data.get("domains", data.get("hosts", []))
                if isinstance(d, str)
            }
        return set()
    except Exception:
        return set()


def api_crtsh(ip: str, session) -> Set[str]:
    """crt.sh certificate-transparency lookup."""
    try:
        resp = safe_request(
            session,
            f"https://crt.sh/?q={ip}&output=json",
            timeout=15,
        )
        data = json.loads(safe_text(resp))
        domains: Set[str] = set()
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    for d in entry.get("name_value", "").split("\n"):
                        domains.add(clean_domain(d))
        return domains
    except Exception:
        return set()


def api_bing(ip: str, session) -> Set[str]:
    """Bing ip: search scraper."""
    try:
        resp = safe_request(
            session,
            f"https://www.bing.com/search?q=ip%3A{ip}&count=30",
            headers=build_headers(referer="https://www.bing.com/"),
            timeout=8,
        )
        text = safe_text(resp)
        domains: Set[str] = set()
        for cite in re.findall(r'<cite[^>]*>(.*?)</cite>', text, re.DOTALL):
            cite = re.sub(r'<[^>]+>', '', cite)
            m = DOMAIN_RE.search(cite)
            if m:
                domains.add(clean_domain(m.group(0)))
        return domains
    except Exception:
        return set()


# ═══════════════════════════════════════════════════════════════
# API SOURCES (require API keys — optional)
# ═══════════════════════════════════════════════════════════════

def api_shodan(ip: str, session, api_key: str = None) -> Set[str]:
    """Shodan DNS reverse lookup (requires API key)."""
    if not api_key:
        return set()
    try:
        resp = safe_request(
            session,
            f"https://api.shodan.io/dns/reverse?ips={ip}&key={api_key}",
            timeout=10,
        )
        data = json.loads(safe_text(resp))
        domains: Set[str] = set()
        if isinstance(data, dict):
            for _, hostnames in data.items():
                if isinstance(hostnames, list):
                    for h in hostnames:
                        domains.add(clean_domain(h))
        return domains
    except Exception:
        return set()


def api_securitytrails(ip: str, session, api_key: str = None) -> Set[str]:
    """SecurityTrails IP children lookup (requires API key)."""
    if not api_key:
        return set()
    try:
        resp = safe_request(
            session,
            f"https://api.securitytrails.com/v1/ips/{ip}/children",
            headers={"APIKEY": api_key},
            timeout=10,
        )
        data = json.loads(safe_text(resp))
        if isinstance(data, dict):
            return {
                clean_domain(r["hostname"])
                for r in data.get("records", [])
                if isinstance(r, dict) and r.get("hostname")
            }
        return set()
    except Exception:
        return set()


def api_chaos(ip: str, session, api_key: str = None) -> Set[str]:
    """ProjectDiscovery Chaos DNS reverse lookup (requires API key)."""
    if not api_key:
        return set()
    try:
        resp = safe_request(
            session,
            f"https://dns.projectdiscovery.io/dns/reverse/{ip}",
            headers={"Authorization": api_key},
            timeout=10,
        )
        data = json.loads(safe_text(resp))
        if isinstance(data, dict) and "domains" in data:
            return {clean_domain(d) for d in data["domains"]}
        return set()
    except Exception:
        return set()


# ═══════════════════════════════════════════════════════════════
# REGISTRY — mirrors bot.py ALL_APIS
# ═══════════════════════════════════════════════════════════════

ALL_APIS = [
    ("RapidDNS",      api_rapiddns,      True),
    ("Webscan",       api_webscan,       True),
    ("xReverseLabs",  api_xreverselabs,  True),
    ("HackerTarget",  api_hackertarget,  True),
    ("ViewDNS",       api_viewdns,       True),
    ("IPinfo",        api_ipinfo,        True),
    ("YouGetSignal",  api_yougetsignal,  True),
    ("DNSLytics",     api_dnslytics,     True),
    ("ReverseIP",     api_reverseip,     True),
    ("Crt.sh",        api_crtsh,         True),
    ("Bing",          api_bing,          False),
]


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

def run_reverse_ip(
    ips: List[str],
    threads: int,
    api_keys: Dict[str, str],
    output_dir: str,
) -> List[str]:
    """
    Reverse-IP lookup for a list of IPs using multiple API sources.

    Parameters
    ----------
    ips : List[str]
        Target IP addresses.
    threads : int
        Number of concurrent worker threads.
    api_keys : Dict[str, str]
        Optional API keys. Supported keys: ``shodan``, ``securitytrails``,
        ``chaos``, ``xreverselabs``.
    output_dir : str
        Directory where ``reverse_ip_domains.txt`` will be saved.

    Returns
    -------
    List[str]
        Sorted list of unique discovered domains.
    """
    if not ips:
        print("  ❌  No IPs provided.")
        return []

    total = len(ips)
    print(f"  🌐  Reverse IP started — {total:,} IPs, {threads} threads")

    # Build the enabled API list (base + optional keyed APIs)
    enabled_apis = list(ALL_APIS)
    if api_keys.get("shodan"):
        enabled_apis.append(("Shodan", api_shodan, True))
    if api_keys.get("securitytrails"):
        enabled_apis.append(("SecurityTrails", api_securitytrails, True))
    if api_keys.get("chaos"):
        enabled_apis.append(("Chaos", api_chaos, True))

    all_domains = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    session = make_session(threads)
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "reverse_ip_domains.txt")

    def worker(ip: str):
        try:
            resolved = resolve_ip(ip)
            if not resolved:
                counter.increment()
                return

            for api_name, api_func, _ in enabled_apis:
                try:
                    time.sleep(0.3)

                    # Pass API key for sources that require / accept one
                    if api_name == "Shodan":
                        found = api_func(resolved, session, api_keys.get("shodan"))
                    elif api_name == "SecurityTrails":
                        found = api_func(resolved, session, api_keys.get("securitytrails"))
                    elif api_name == "Chaos":
                        found = api_func(resolved, session, api_keys.get("chaos"))
                    elif api_name == "xReverseLabs":
                        found = api_func(resolved, session, api_keys.get("xreverselabs", "unknown"))
                    else:
                        found = api_func(resolved, session)

                    valid = {d for d in found if d and "." in d}
                    for d in valid:
                        all_domains.append(d)
                        append_result(out_file, d)
                except Exception:
                    pass

            counter.increment()
        except Exception:
            counter.increment()

    # Run workers
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(worker, ip): ip for ip in ips}
        for future in as_completed(futures):
            # Print progress after each IP completes
            print_progress(
                counter.value, total,
                prefix="IP→Domain",
                suffix=f"| 💎 {len(all_domains):,} domains",
            )

    session.close()

    # Deduplicate + sort
    unique_domains = sorted({d for d in all_domains.copy() if d})

    # Write final deduplicated file
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_domains) + "\n")
    except Exception as e:
        print(f"\n  ⚠️  Failed to write {out_file}: {e}")

    elapsed = time.time() - start_t
    print(f"\n  ✅  Reverse IP done — {len(unique_domains):,} unique domains in {elapsed:.1f}s")
    return unique_domains
