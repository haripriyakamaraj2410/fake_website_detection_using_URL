"""Opt-in, metadata-only URL checks. Never fetches or renders page bodies."""

from __future__ import annotations

import socket
import ssl
import time
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _StopRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def run_live_checks(url: str, timeout: float = 3.0) -> list[dict[str, str]]:
    """Check DNS, TLS, WHOIS age, and a bounded HEAD redirect chain."""
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    host = parsed.hostname
    if not host:
        return [{"check": "Live checks", "result": "Unavailable: no valid hostname."}]
    results: list[dict[str, str]] = []
    addresses: list[str] = []
    try:
        records = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
        results.append({"check": "DNS", "result": f"Resolved: {', '.join(addresses[:3])}"})
    except (OSError, ValueError) as exc:
        results.append({"check": "DNS", "result": f"Could not resolve: {exc}"})

    public_destination = bool(addresses) and all(
        ipaddress.ip_address(address.split("%", 1)[0]).is_global for address in addresses
    )
    if not public_destination:
        results.append({
            "check": "Network safety",
            "result": "TLS, WHOIS, and HEAD checks skipped: hostname did not resolve exclusively to public IP addresses.",
        })
        return results

    if parsed.scheme.lower() == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as secured:
                    cert = secured.getpeercert()
                issued = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - issued).days
                remaining = (expiry - datetime.now(timezone.utc)).days
                results.append({"check": "TLS certificate", "result": f"Valid for this connection; issued {age} day(s) ago, expires in {remaining} day(s)."})
        except (OSError, ValueError, KeyError, ssl.SSLError) as exc:
                results.append({"check": "TLS certificate", "result": f"Could not validate: {exc}"})
    else:
        results.append({"check": "TLS certificate", "result": "Not checked: URL does not use HTTPS."})

    try:
        whois_result = _whois_domain_age(host, timeout)
        results.append({"check": "WHOIS domain age", "result": whois_result})
    except (OSError, ValueError, TimeoutError) as exc:
        results.append({"check": "WHOIS domain age", "result": f"Could not check: {exc}"})

    try:
        parsed_start = urlsplit(url if "://" in url else f"https://{url}")
        safe_netloc = parsed_start.hostname or ""
        if ":" in safe_netloc and not safe_netloc.startswith("["):
            safe_netloc = f"[{safe_netloc}]"
        if parsed_start.port:
            safe_netloc += f":{parsed_start.port}"
        safe_url = urlunsplit((
            parsed_start.scheme or "https",
            safe_netloc,
            parsed_start.path,
            parsed_start.query,
            "",
        ))
        current = safe_url
        started = time.monotonic()
        hops = []
        opener = build_opener(_StopRedirects)
        for hop in range(5):
                hop_parsed = urlsplit(current)
                if hop_parsed.scheme not in {"http", "https"} or not hop_parsed.hostname:
                    hops.append("redirect target blocked (unsupported URL scheme)")
                    break
                hop_records = socket.getaddrinfo(
                    hop_parsed.hostname, hop_parsed.port or (443 if hop_parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
                hop_addresses = {record[4][0] for record in hop_records}
                if not hop_addresses or any(not ipaddress.ip_address(address.split("%", 1)[0]).is_global for address in hop_addresses):
                    hops.append("redirect target blocked (not a public address)")
                    break
                request = Request(current, method="HEAD")
                try:
                    response = opener.open(request, timeout=timeout)
                    status = response.status
                    response.close()
                    hops.append(f"{status} {hop_parsed.hostname}")
                    break
                except Exception as exc:
                    location = getattr(exc, "headers", {}).get("Location") if getattr(exc, "headers", None) else None
                    code = getattr(exc, "code", None)
                    if code in {301, 302, 303, 307, 308} and location:
                        hops.append(f"{code} {hop_parsed.hostname}")
                        current = urljoin(current, location)
                        continue
                    hops.append(f"{code or 'error'} {hop_parsed.hostname}: {exc}")
                    break
        else:
                hops.append("stopped after 5 HEAD requests")
        results.append({"check": "HEAD redirect chain (no body)", "result": " → ".join(hops) + f"; {time.monotonic() - started:.1f}s."})
    except (OSError, ValueError) as exc:
        results.append({"check": "HEAD redirect chain (no body)", "result": f"Could not check: {exc}"})
    return results


def _whois_domain_age(host: str, timeout: float) -> str:
    """Query the IANA WHOIS referral and registry with bounded socket timeouts."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "Unavailable: WHOIS domain age does not apply to a raw IP address."
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    if len(labels) < 2:
        return "Unavailable: this host does not have a registrable domain."
    domain = ".".join(labels[-2:])
    tld = labels[-1]

    def query(server: str, term: str) -> str:
        with socket.create_connection((server, 43), timeout=timeout) as connection:
                connection.settimeout(timeout)
                connection.sendall((term + "\r\n").encode("ascii", errors="ignore"))
                chunks = []
                received = 0
                while received < 65536:
                    try:
                        chunk = connection.recv(min(4096, 65536 - received))
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    received += len(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")

    referral_data = query("whois.iana.org", tld)
    referral_match = re.search(r"(?im)^whois:\s*([^\s]+)", referral_data)
    if not referral_match:
        return "Unavailable: no WHOIS registry referral was returned."
    whois_data = query(referral_match.group(1), domain)
    date_match = re.search(
        r"(?im)^(?:Creation Date|Created|Registered On|created|registration date):\s*(.+?)\s*$",
        whois_data,
    )
    if not date_match:
        return "Unavailable: registry returned no recognized creation date."
    raw_date = date_match.group(1)
    parsed_date = None
    for date_format in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d"):
        try:
                parsed_date = datetime.strptime(raw_date[:20], date_format).replace(tzinfo=timezone.utc)
                break
        except ValueError:
                continue
    if parsed_date is None:
        return f"Registration date returned by WHOIS: {raw_date} (age could not be parsed)."
    age_days = (datetime.now(timezone.utc) - parsed_date).days
    return f"Registered {age_days} day(s) ago ({parsed_date.date().isoformat()}); registry data may be incomplete."
