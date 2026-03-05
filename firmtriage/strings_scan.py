'''
Inputs
	•	data: bytes
	•	config like min_len=4, max_results=200

Outputs (dict)
	•	count_total
	•	top_samples (list of strings)
	•	hits (categorized interesting strings)
	•	urls
	•	ips
	•	file_paths
	•	crypto_markers (e.g., “BEGIN CERTIFICATE”, “ssh-rsa”, “ed25519”)
	•	debug_markers (e.g., “JTAG”, “UART”, “console”, “debug”, “panic”)
	•	update_markers (e.g., “rollback”, “firmware”, “update”, “slot”, “bank”)
'''
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set, Iterable, Optional
import re
import ipaddress


# -----------------------------
# Config
# -----------------------------

@dataclass(frozen=True)
class StringsConfig:
    min_len: int = 4
    max_results: int = 200
    # If True, only allow mostly printable ASCII.
    strict_printable: bool = True


# -----------------------------
# Regex patterns (v1)
# -----------------------------

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+\b", re.IGNORECASE)

# Simple-ish path heuristics (tune later)
POSIX_PATH_RE = re.compile(r"(?:/[^ \t\r\n\"']+)+")
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^ \t\r\n\"']+\\)*[^ \t\r\n\"']+")

# Basic IPv4 candidate (validated with ipaddress)
IPV4_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# -----------------------------
# Marker dictionaries (v1)
# -----------------------------

CRYPTO_MARKERS = [
    "BEGIN CERTIFICATE",
    "BEGIN PUBLIC KEY",
    "ssh-rsa",
    "ed25519",
    "ECDSA",
    "RSA",
    "AES",
    "HMAC",
    "SHA256",
    "SHA-256",
]

DEBUG_MARKERS = [
    "JTAG",
    "UART",
    "console",
    "debug",
    "panic",
    "assert",
    "stacktrace",
    "crash",
]

UPDATE_MARKERS = [
    "rollback",
    "anti-rollback",
    "firmware",
    "update",
    "slot",
    "bank",
    "A/B",
    "dual bank",
    "recovery",
]


# -----------------------------
# Core extraction
# -----------------------------

def _is_printable_ascii_byte(b: int) -> bool:
    # Space (0x20) to ~ (0x7E) plus common whitespace can be allowed.
    return (0x20 <= b <= 0x7E)

def extract_ascii_strings(data: bytes, min_len: int) -> List[str]:
    """
    Extract contiguous ASCII-printable strings from bytes.
    Similar to Unix `strings` default behavior (but strict printable by default).
    """
    if min_len <= 0:
        raise ValueError("min_len must be > 0")

    out: List[str] = []
    buf: bytearray = bytearray()

    for b in data:
        if _is_printable_ascii_byte(b):
            buf.append(b)
        else:
            if len(buf) >= min_len:
                out.append(buf.decode("ascii", errors="ignore"))
            buf.clear()

    # tail
    if len(buf) >= min_len:
        out.append(buf.decode("ascii", errors="ignore"))

    return out


# -----------------------------
# Categorization helpers
# -----------------------------

def _find_urls(s: str) -> List[str]:
    return URL_RE.findall(s)

def _find_paths(s: str) -> List[str]:
    hits = []
    hits.extend(POSIX_PATH_RE.findall(s))
    hits.extend(WIN_PATH_RE.findall(s))
    return hits

def _find_ips(s: str) -> List[str]:
    candidates = IPV4_CANDIDATE_RE.findall(s)
    valid: List[str] = []
    for c in candidates:
        try:
            ipaddress.ip_address(c)
            valid.append(c)
        except ValueError:
            pass
    return valid

def _marker_hits(s: str, markers: List[str]) -> List[str]:
    s_low = s.lower()
    found = []
    for m in markers:
        if m.lower() in s_low:
            found.append(m)
    return found


# -----------------------------
# Public API
# -----------------------------

def strings_scan(data: bytes, config: Optional[StringsConfig] = None) -> Dict:
    """
    Returns:
      {
        "count_total": int,
        "top_samples": [str],
        "hits": { ... categorized marker hits ... },
        "urls": [str],
        "ips": [str],
        "file_paths": [str],
        "crypto_markers": [str],
        "debug_markers": [str],
        "update_markers": [str],
      }
    """
    if config is None:
        config = StringsConfig()

    strings = extract_ascii_strings(data, min_len=config.min_len)

    # Cap results early so huge files don't blow memory/UI
    count_total = len(strings)
    top_samples = strings[: config.max_results]

    urls: Set[str] = set()
    ips: Set[str] = set()
    paths: Set[str] = set()

    crypto_hits: Set[str] = set()
    debug_hits: Set[str] = set()
    update_hits: Set[str] = set()

    for s in top_samples:
        for u in _find_urls(s):
            urls.add(u)
        for ip in _find_ips(s):
            ips.add(ip)
        for p in _find_paths(s):
            paths.add(p)

        for m in _marker_hits(s, CRYPTO_MARKERS):
            crypto_hits.add(m)
        for m in _marker_hits(s, DEBUG_MARKERS):
            debug_hits.add(m)
        for m in _marker_hits(s, UPDATE_MARKERS):
            update_hits.add(m)

    # Optional: summarize where hits came from (v1: minimal)
    hits = {
        "crypto": sorted(crypto_hits),
        "debug": sorted(debug_hits),
        "update": sorted(update_hits),
    }

    return {
        "count_total": count_total,
        "top_samples": top_samples,
        "hits": hits,
        "urls": sorted(urls),
        "ips": sorted(ips),
        "file_paths": sorted(paths),
        "crypto_markers": sorted(crypto_hits),
        "debug_markers": sorted(debug_hits),
        "update_markers": sorted(update_hits),
    }