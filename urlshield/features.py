"""URL-only feature extraction used by the supplied 23-feature models."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

FEATURE_COLUMNS = [
    "url_len",
    "@",
    "?",
    "-",
    "=",
    ".",
    "#",
    "%",
    "+",
    "$",
    "!",
    "*",
    '"',
    "//",
    "abnormal_url",
    "https",
    "digits",
    "letters",
    "having_ip_address",
    "path_length",
    "query_length",
    "subdirectory_count",
    "suspicious_word_count",
]

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "paypal", "password", "confirm", "wallet", "payment", "support",
    "webscr", "recover", "authentication", "invoice",
)


def _is_ip_address(hostname: str) -> bool:
    """Return whether a hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def extract_features(url: str) -> list[int]:
    """Extract the model's 23 features, preserving its required column order.

    Preprocessing matches the supplied model contract: trim whitespace and
    remove ``www.`` before counting. This function never makes a network call.
    """
    cleaned = url.strip().replace("www.", "")
    lower_url = cleaned.lower()
    parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}")
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    host_for_validation = hostname

    if not host_for_validation and parsed.netloc:
        host_for_validation = parsed.netloc.split("@")[-1].split(":")[0]

    values = [
        len(cleaned),
        cleaned.count("@"),
        cleaned.count("?"),
        cleaned.count("-"),
        cleaned.count("="),
        cleaned.count("."),
        cleaned.count("#"),
        cleaned.count("%"),
        cleaned.count("+"),
        cleaned.count("$"),
        cleaned.count("!"),
        cleaned.count("*"),
        cleaned.count('"'),
        cleaned.count("//"),
        int("@" in cleaned or bool(hostname and hostname not in lower_url)),
        int(parsed.scheme.lower() == "https"),
        sum(character.isdigit() for character in cleaned),
        sum(character.isalpha() for character in cleaned),
        int(_is_ip_address(host_for_validation)),
        len(path),
        len(query),
        len([part for part in path.split("/") if part]),
        sum(word in lower_url for word in SUSPICIOUS_WORDS),
    ]
    return values


def feature_dict(url: str) -> dict[str, int]:
    """Return extracted features keyed by the model's exact feature names."""
    return dict(zip(FEATURE_COLUMNS, extract_features(url)))


def normalized_url(url: str) -> str:
    """Trim the URL and remove the ``www.`` prefix per the model contract."""
    return url.strip().replace("www.", "")


def validate_url_input(url: str, max_length: int = 8192) -> tuple[bool, str]:
    """Validate a URL as text without resolving or opening it."""
    value = url.strip()
    if not value:
        return False, "Enter a URL to scan."
    if len(value) > max_length:
        return False, f"URL is too long (maximum {max_length:,} characters)."
    host_port = re.match(r"^[^/:?#]+:\d+(?:[/#?]|$)", value)
    explicit_scheme = None if host_port and "://" not in value else re.match(
        r"^([A-Za-z][A-Za-z0-9+.-]*):", value
    )
    scheme = explicit_scheme.group(1).lower() if explicit_scheme else ""
    if scheme and scheme not in {"http", "https"}:
        return False, "Only HTTP and HTTPS URLs are supported."
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return False, "This URL is malformed (for example, its hostname or port is invalid)."
    if not hostname:
        return False, "This does not look like a URL with a hostname."
    if any(character.isspace() for character in hostname):
        return False, "The hostname contains whitespace and is not valid."
    return True, ""
