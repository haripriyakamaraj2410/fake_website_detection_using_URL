"""Explainable indicators measured directly from a submitted URL."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit

from .features import SUSPICIOUS_WORDS, _is_ip_address

POPULAR_BRANDS = (
    "amazon", "apple", "facebook", "google", "instagram", "microsoft",
    "netflix", "paypal", "sbi", "whatsapp", "youtube",
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "buff.ly"}
RARE_TLDS = {"zip", "mov", "click", "country", "gq", "tk", "ml", "cf", "work", "top"}
EXECUTABLE_EXTENSIONS = {".exe", ".apk", ".zip", ".scr", ".msi", ".dmg", ".bat"}
IDN_LOOKALIKE_CHARS = set("а е о р с х і ј ӏ ԁ".replace(" ", ""))


def _parsed_url(url: str):
    value = url.strip()
    return urlsplit(value if "://" in value else f"//{value}")


def _brand_match(domain: str) -> tuple[str, float] | None:
    normalized = re.sub(r"[^a-z0-9]", "", domain.lower().split(".")[0])
    if len(normalized) < 4:
        return None
    candidates = [(brand, SequenceMatcher(None, normalized, brand).ratio()) for brand in POPULAR_BRANDS]
    best_brand, score = max(candidates, key=lambda item: item[1])
    if normalized != best_brand and score >= 0.78:
        return best_brand, score
    return None


def analyze_signals(url: str) -> dict:
    """Return only evidence supported by URL text and extracted measurements."""
    parsed = _parsed_url(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    full = url.strip()
    lower = full.lower()
    labels = [label for label in host.split(".") if label]
    tld = labels[-1] if len(labels) > 1 else ""
    flags: list[dict[str, str]] = []
    greens: list[dict[str, str]] = []

    def red(name: str, message: str, value: str) -> None:
        flags.append({"name": name, "message": message, "value": value})

    def green(name: str, message: str, value: str) -> None:
        greens.append({"name": name, "message": message, "value": value})

    if _is_ip_address(host):
        red("raw_ip", "The host is a raw IP address, which is unusual for a public sign-in site.", host)
    if "@" in full:
        red("at_symbol", "An @ symbol can hide the real destination before it.", f'{full.count("@")} occurrence(s)')
    if len(full) > 100:
        red("long_url", "This URL is unusually long and may be obscuring its destination.", f"{len(full)} characters")
    if len([p for p in path.split("/") if p]) >= 4:
        red("deep_path", "The URL has many nested path sections.", f'{len([p for p in path.split("/") if p])} sections')
    if full.count("-") >= 3:
        red("hyphens", "Several hyphens appear in the URL, which can make a look-alike address harder to spot.", f"{full.count('-')} hyphens")
    digits = sum(character.isdigit() for character in host)
    letters = sum(character.isalpha() for character in host)
    if digits >= 5:
        red("host_digits", "The hostname contains an unusually large number of digits.", f"{digits} digits")
    terms = sorted({word for word in SUSPICIOUS_WORDS if word in lower})
    if terms:
        red("suspicious_words", "The URL includes terms often used in account or payment lures.", ", ".join(terms))
    if parsed.scheme.lower() != "https":
        red("no_https", "The URL does not use HTTPS; this alone does not prove it is malicious.", parsed.scheme or "no scheme")
    if "%" in full:
        red("encoded_chars", "Percent-encoding is present and can make URL text less readable.", f"{full.count('%')} percent sign(s)")
    if len(labels) >= 5:
        red("subdomains", "The hostname has many dot-separated labels.", f"{len(labels) - 2} subdomain label(s)")
    if tld in RARE_TLDS:
        red("rare_tld", "This top-level domain is less commonly used and appears in some abuse reports.", f".{tld}")
    if any(character in IDN_LOOKALIKE_CHARS for character in host):
        red("idn", "The hostname contains non-Latin characters that may resemble Latin letters.", "non-ASCII look-alike character(s)")
    if host in SHORTENERS:
        red("shortener", "This is a URL-shortening domain, so the destination is not visible here.", host)
    brand_match = _brand_match(host)
    if brand_match:
        brand, similarity = brand_match
        red("brand_lookalike", f"The hostname resembles the brand name {brand}, but is not an exact match.", f"{similarity:.0%} textual similarity")
    extension = next((ext for ext in EXECUTABLE_EXTENSIONS if path.lower().endswith(ext)), None)
    if extension:
        red("executable", "The path ends in a downloadable or executable file extension.", extension)

    if parsed.scheme.lower() == "https":
        green("https", "The URL uses HTTPS for its connection.", "https")
    if host and not _is_ip_address(host):
        green("named_host", "The destination is a named hostname rather than a raw IP address.", host)
    if len(full) <= 75:
        green("moderate_length", "The URL is not unusually long.", f"{len(full)} characters")
    if not any(key in {flag["name"] for flag in flags} for key in ("suspicious_words", "brand_lookalike")):
        green("no_common_lure", "No configured account-lure terms or brand look-alike were detected.", "0 detected")

    return {
        "red_flags": flags,
        "green_flags": greens,
        "host": host,
        "protocol": parsed.scheme.lower() or "not specified",
        "path": path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "tld": tld,
        "subdomains": ".".join(labels[:-2]) if len(labels) > 2 else "",
        "domain": ".".join(labels[-2:]) if len(labels) >= 2 else host,
        "host_digit_to_letter_ratio": f"{digits}/{letters}" if letters else str(digits),
    }
