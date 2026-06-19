# ═══════════════════════════════════════════════════════════════
# RECON ALL — Shared Utilities
# ═══════════════════════════════════════════════════════════════
import os
import re
import sys
import json
import time
import random
import socket
import struct
import threading
import requests
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse, urljoin, quote

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from urllib3.exceptions import InsecureRequestWarning
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    BeautifulSoup = None

# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

SKIP_PREFIXES = (
    'localhost', '127.', '0.0.0.0', '::1',
    'ns0.', 'ns3.', 'ns4.', 'ns5.', 'dns.', 'dns1.', 'dns2.'
)

DOMAIN_RE = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

ADMIN_PATHS = ['/admin', '/wp-admin', '/administrator', '/cpanel', '/plesk', '/webmail', '/login', '/user']

SHELL_PATTERNS = {
    'shell': ['>public_html', '<span>Upload file:', 'name="uploader" id="uploader">', 'Upload File : <input'],
    'uploader': ['type="submit" id="_upl" value="Upload">'],
    'mailer': ['Leaf PHPMailer', '>alexusMailer 2.0<'],
    'password': ['method=post>Password:', '<input type=password name=pass'],
}
ERROR_PATTERNS = ['No route found for "', 'Apache2', 'ErrorException']

HUNTER_PATHS = [
    '/.env', '/.env.backup', '/.env.local', '/.env.production',
    '/phpinfo.php', '/phpinfo', '/info.php', '/.debug', '/debug',
    '/api/.env', '/laravel/.env', '/admin/.env', '/vendor/.env',
    '/config/.env', '/app/.env', '/core/.env', '/env',
    '/.env.development', '/.env.staging', '/.env.example',
]

API_KEY_PATTERNS = {
    "Laravel APP_KEY":
        re.compile(r'APP_KEY\s*=\s*base64:([A-Za-z0-9+/=]{32,64})'),
    "OpenAI (Standard/Proj/SvcAcct)":
        re.compile(r'(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,180})'),
    "Anthropic (Claude)":
        re.compile(r'(sk-ant-(?:api03-)?[A-Za-z0-9_\-]{80,120})'),
    "Google Gemini / GCP":
        re.compile(r'(AIzaSy[A-Za-z0-9_\-]{33})'),
    "Hugging Face":
        re.compile(r'(hf_[a-zA-Z0-9]{34,40})'),
    "Cohere":
        re.compile(r'(?<![a-zA-Z0-9])(co-[a-zA-Z0-9]{40})(?![a-zA-Z0-9])'),
    "Replicate":
        re.compile(r'(r8_[a-zA-Z0-9]{40})'),
    "NVIDIA NGC/NIM":
        re.compile(r'(nvapi-[A-Za-z0-9_\-]{60,80})'),
    "GitHub PAT/OAuth":
        re.compile(r'(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|gho_[a-zA-Z0-9]{36})'),
    "DeepSeek / Kimi":
        re.compile(r'(?<![a-zA-Z0-9\-_])(sk-[a-zA-Z0-9]{32})(?![a-zA-Z0-9\-_])'),
    "AWS Access Key ID":
        re.compile(r'(?<![A-Z0-9])((?:AKIA|AGPA|AIPA|AROA|ASCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])'),
    "AWS Secret Access Key":
        re.compile(r'(?i)(?:aws|secret).{0,20}?([A-Za-z0-9/+=]{40})'),
    "Stripe Live Secret Key":
        re.compile(r'(sk_live_[a-zA-Z0-9]{24,})'),
    "Stripe Test Secret Key":
        re.compile(r'(sk_test_[a-zA-Z0-9]{24,})'),
    "SendGrid API Key":
        re.compile(r'(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})'),
    "Twilio Auth Token":
        re.compile(r'(?i)twilio.{0,30}?([a-f0-9]{32})'),
    "Mailgun API Key":
        re.compile(r'(key-[a-zA-Z0-9]{32})'),
    "Slack Bot/App Token":
        re.compile(r'(xox[baprs]-[a-zA-Z0-9\-]{10,72})'),
    "Slack Webhook URL":
        re.compile(r'(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)'),
    "Generic JWT":
        re.compile(r'(eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_+/=]{10,})'),
    "RSA/EC Private Key":
        re.compile(r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)'),
}

PATTERN_PRIORITY = [
    "Laravel APP_KEY",
    "Anthropic (Claude)",
    "GitHub PAT/OAuth",
    "Slack Webhook URL",
    "Slack Bot/App Token",
    "SendGrid API Key",
    "AWS Access Key ID",
    "Stripe Live Secret Key",
    "Stripe Test Secret Key",
    "Google Gemini / GCP",
    "Hugging Face",
    "Replicate",
    "NVIDIA NGC/NIM",
    "OpenAI (Standard/Proj/SvcAcct)",
    "Cohere",
    "Twilio Auth Token",
    "Mailgun API Key",
    "AWS Secret Access Key",
    "DeepSeek / Kimi",
    "RSA/EC Private Key",
    "Generic JWT",
]


# ═══════════════════════════════════════════════════════════════
# THREAD-SAFE HELPERS
# ═══════════════════════════════════════════════════════════════
class ThreadSafeCounter:
    def __init__(self):
        self._val = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self._val += 1

    @property
    def value(self):
        with self._lock:
            return self._val


class ThreadSafeList:
    def __init__(self):
        self._data: List[str] = []
        self._lock = threading.Lock()

    def append(self, item: str):
        with self._lock:
            self._data.append(item)

    def copy(self) -> List[str]:
        with self._lock:
            return list(self._data)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


# Thread-safe file write lock
_file_write_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════
# CORE HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════
def rotate_ua(index=0):
    return USER_AGENTS[index % len(USER_AGENTS)]


def build_headers(ua=None, referer="https://www.google.com"):
    return {
        "User-Agent": ua or rotate_ua(random.randint(0, len(USER_AGENTS) - 1)),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Referer": referer,
        "Upgrade-Insecure-Requests": "1",
    }


def safe_text(resp):
    """Safely extract text from a requests Response object."""
    try:
        return resp.content.decode("utf-8", errors="ignore")
    except Exception:
        try:
            return resp.text
        except Exception:
            return ""


def clean_domain(raw):
    """Extract and clean a valid domain from raw input."""
    if not raw or not isinstance(raw, str):
        return ""
    raw = raw.strip().lower()
    # Strip protocol
    for prefix in ("https://", "http://", "ftp://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    # Strip path/query
    raw = raw.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    raw = raw.strip().rstrip(".")
    if not raw:
        return ""
    if any(raw.startswith(p) for p in SKIP_PREFIXES):
        return ""
    if IP_RE.match(raw):
        return ""
    if DOMAIN_RE.fullmatch(raw):
        return raw
    m = DOMAIN_RE.search(raw)
    return m.group(0) if m else ""


def normalize_host(raw):
    """Normalize a host string — strip protocol, port, path."""
    if not raw or not isinstance(raw, str):
        return ""
    raw = raw.strip()
    for prefix in ("https://", "http://", "ftp://"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    if ":" in raw:
        parts = raw.rsplit(":", 1)
        if parts[1].isdigit():
            raw = parts[0]
    return raw.strip().rstrip(".").lower()


def resolve_ip(host):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def safe_request(session, url, headers=None, timeout=15, method="GET", data=None):
    """Safe HTTP request wrapper with error handling."""
    try:
        if headers is None:
            headers = build_headers()
        if method.upper() == "POST":
            return session.post(url, headers=headers, timeout=timeout, verify=False,
                                data=data, allow_redirects=True)
        return session.get(url, headers=headers, timeout=timeout, verify=False,
                           allow_redirects=True)
    except Exception:
        return None


def make_session(threads=50):
    """Create a requests.Session with connection pooling."""
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    return session


# ═══════════════════════════════════════════════════════════════
# PORT / IP HELPERS
# ═══════════════════════════════════════════════════════════════
def strip_port(ip_port: str) -> str:
    """Remove :port suffix from IP:Port string. Returns just the IP."""
    if not ip_port:
        return ""
    ip_port = ip_port.strip()
    if ":" in ip_port:
        parts = ip_port.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[0]
    return ip_port


def extract_unique_ips(ip_port_list: List[str]) -> List[str]:
    """Strip ports and deduplicate IPs."""
    seen = set()
    result = []
    for entry in ip_port_list:
        ip = strip_port(entry)
        if ip and ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def extract_root_domains(domain_list: List[str]) -> Set[str]:
    """Extract unique root domains (e.g., sub.example.com → example.com)."""
    roots = set()
    for domain in domain_list:
        domain = domain.strip().lower()
        if not domain:
            continue
        if TLDEXTRACT_AVAILABLE:
            ext = tldextract.extract(domain)
            if ext.domain and ext.suffix:
                root = f"{ext.domain}.{ext.suffix}"
                roots.add(root)
        else:
            # Fallback: take last 2 parts
            parts = domain.split(".")
            if len(parts) >= 2:
                roots.add(".".join(parts[-2:]))
    return roots


def filter_by_port(ip_port_list: List[str], ports: List[int]) -> List[str]:
    """Filter IP:Port list to only include entries matching given ports."""
    result = []
    for entry in ip_port_list:
        entry = entry.strip()
        if ":" in entry:
            parts = entry.rsplit(":", 1)
            if parts[1].isdigit() and int(parts[1]) in ports:
                result.append(entry)
    return result


# ═══════════════════════════════════════════════════════════════
# FILE HELPERS
# ═══════════════════════════════════════════════════════════════
def append_result(filepath: str, line: str):
    """Thread-safe append a line to a result file."""
    with _file_write_lock:
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(line.rstrip("\n") + "\n")
        except Exception:
            pass


def write_results(filepath: str, lines: List[str]):
    """Write a list of lines to a file (overwrite)."""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line.rstrip("\n") + "\n")
    except Exception as e:
        print(f"  ⚠️  Failed to write {filepath}: {e}")


def read_lines(filepath: str) -> List[str]:
    """Read lines from a file, stripping whitespace."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"  ⚠️  Failed to read {filepath}: {e}")
        return []


# ═══════════════════════════════════════════════════════════════
# CLI OUTPUT HELPERS
# ═══════════════════════════════════════════════════════════════
def print_banner():
    """Print the tool banner."""
    banner = r"""
 ╔══════════════════════════════════════════════════════════════╗
 ║            🎯  RECON ALL — Full Pipeline Scanner            ║
 ║         Chain Every Feature. One Command. Zero Gaps.        ║
 ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_phase(phase_num: int, total: int, name: str, icon: str = "🔍"):
    """Print a phase header."""
    width = 60
    print()
    print("═" * width)
    print(f"  {icon}  PHASE {phase_num}/{total}: {name}")
    print("═" * width)


def print_phase_done(name: str, count: int, elapsed: float):
    """Print phase completion summary."""
    print(f"  ✅  {name} complete — {count:,} results in {elapsed:.1f}s")
    print()


def print_phase_skip(name: str, reason: str):
    """Print phase skip message."""
    print(f"  ⏭️   {name} skipped — {reason}")
    print()


def print_phase_fail(name: str, error: str):
    """Print phase failure message."""
    print(f"  ❌  {name} failed — {error}")
    print()


def print_progress(current: int, total: int, prefix: str = "", suffix: str = ""):
    """Print an in-place progress bar."""
    if total == 0:
        return
    pct = current / total
    bar_len = 30
    filled = int(bar_len * pct)
    bar = "█" * filled + "░" * (bar_len - filled)
    line = f"\r  {prefix} [{bar}] {pct*100:.1f}% ({current:,}/{total:,}) {suffix}"
    sys.stdout.write(line)
    sys.stdout.flush()
    if current >= total:
        print()


def print_final_report(results: Dict[str, Any], output_dir: str, total_time: float):
    """Print the final summary report."""
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    📊  FINAL REPORT                        ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    for phase_name, data in results.items():
        count = data.get("count", 0)
        elapsed = data.get("elapsed", 0)
        status = data.get("status", "unknown")
        icon = "✅" if status == "done" else ("⏭️" if status == "skipped" else "❌")
        count_str = f"{count:,} results" if count > 0 else "—"
        time_str = f"{elapsed:.1f}s" if elapsed > 0 else "—"
        print(f"  {icon}  {phase_name:<25} {count_str:<20} {time_str}")

    print()
    print(f"  📁  Results saved to: {output_dir}")
    print(f"  ⏱️   Total time: {total_time:.1f}s ({total_time/60:.1f} min)")
    print()
