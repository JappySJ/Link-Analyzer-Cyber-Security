"""
TLS/SSL certificate and PKI inspection.

THE BUG THIS MODULE EXISTS TO FIX
--------------------------------
The original LTAT.py called ssl.getpeercert() to read certificate fields. That
call returns an EMPTY DICT whenever the socket was wrapped with
verify_mode = CERT_NONE - which is exactly the situation we care about most,
because self-signed and expired certificates are the ones a phishing site
serves. The old code therefore reported nothing precisely when there was
something to report.

The fix, implemented below:

  * Never trust the dict form for an untrusted certificate. Always fetch the
    raw bytes with getpeercert(binary_form=True) and parse that DER with the
    `cryptography` library (x509.load_der_x509_certificate), which does not
    care whether verification succeeded.

  * Do a TWO-PASS handshake:
      Pass 1 - a normal verifying context. If it succeeds we learn that the
               chain is trusted AND the hostname matches, and we grab the DER.
      Pass 2 - only if pass 1 failed: reconnect with check_hostname=False and
               CERT_NONE purely to READ the certificate the server offers, and
               record WHY pass 1 failed.

  * datetime handling is timezone-aware everywhere (datetime.now(timezone.utc),
    never the deprecated datetime.utcnow()), and the not_valid_after_utc /
    not_valid_before_utc properties introduced in cryptography 42 are used when
    present, falling back to the older names via getattr() on older versions.

Nothing in here ever raises to the caller. Every failure path returns a dict
with a "status" the UI can render.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from app.config import CERT_TIMEOUT, FREE_CA_ISSUERS

# Status values returned in the "status" key.
STATUS_OK = "ok"                  # we obtained and parsed a certificate
STATUS_UNREACHABLE = "unreachable"  # nothing answered on the TLS port
STATUS_NO_TLS = "no_tls"          # host answered but spoke no usable TLS
STATUS_ERROR = "error"            # anything else, message in "error"


def _empty_result(status: str, error: str = "") -> dict:
    """
    A fully populated result with every key present.

    Callers and the Jinja templates can always index the same keys, so an
    unreachable host renders a clean empty state instead of a KeyError.
    """
    return {
        "status": status,
        "error": error,
        "chain_trusted": False,
        "hostname_match": False,
        "self_signed": False,
        "is_free_ca": False,
        "is_expired": False,
        "issuer_org": "",
        "issuer_cn": "",
        "subject_cn": "",
        "subject_org": "",
        "valid_from": "",
        "valid_to": "",
        "days_to_expiry": None,
        "validity_days": None,
        "tls_version": "",
        "cipher": "",
        "san_count": 0,
        "san_sample": [],
        "sha256_fingerprint": "",
    }


def _name_attribute(name: x509.Name, oid) -> str:
    """Read one RDN (e.g. common name) out of an X.509 Name, or '' if absent."""
    try:
        values = name.get_attributes_for_oid(oid)
        if not values:
            return ""
        value = values[0].value
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    except Exception:
        return ""


def _cert_datetime(cert: x509.Certificate, field: str) -> datetime | None:
    """
    Read not_valid_before / not_valid_after as a timezone-aware UTC datetime.

    cryptography >= 42 deprecates the naive `not_valid_after` in favour of
    `not_valid_after_utc`. getattr() picks the new name when it exists and
    silently falls back on older releases, so this works on both.
    """
    try:
        value = getattr(cert, f"{field}_utc", None)
        if value is None:
            value = getattr(cert, field, None)
        if value is None:
            return None
        # The legacy attribute is naive but documented as UTC - attach the tzinfo
        # so every later comparison is between aware datetimes.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value
    except Exception:
        return None


def _hostname_matches(cert: x509.Certificate, hostname: str) -> bool:
    """
    Check the hostname against the SAN list, falling back to the subject CN.

    Handles a single leading wildcard label ('*.example.com' matches
    'www.example.com' but not 'a.b.example.com'), which is what RFC 6125
    permits and what browsers implement.
    """
    host = (hostname or "").lower().rstrip(".")
    if not host:
        return False

    names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names.extend(san_ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass

    if not names:
        cn = _name_attribute(cert.subject, NameOID.COMMON_NAME)
        if cn:
            names.append(cn)

    for name in names:
        candidate = (name or "").lower().rstrip(".")
        if not candidate:
            continue
        if candidate == host:
            return True
        if candidate.startswith("*."):
            suffix = candidate[1:]                 # '.example.com'
            if host.endswith(suffix):
                # A wildcard covers exactly one label, so the remaining prefix
                # must not itself contain a dot.
                prefix = host[: -len(suffix)]
                if prefix and "." not in prefix:
                    return True
    return False


def _get_san_list(cert: x509.Certificate) -> list[str]:
    """All DNS names in the SAN extension ([] when the extension is absent)."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        return []


def _handshake(hostname: str, port: int, timeout: int, verify: bool):
    """
    One TLS handshake.

    Returns (der_bytes, tls_version, cipher_name, error_message). On success
    error_message is None; on failure the first three are None.

    We always take the certificate as DER bytes - the parsed dict from
    getpeercert() is deliberately never used, because it is empty under
    CERT_NONE.
    """
    try:
        if verify:
            context = ssl.create_default_context()
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                cipher_info = tls_sock.cipher()
                return (
                    der,
                    tls_sock.version() or "",
                    cipher_info[0] if cipher_info else "",
                    None,
                )
    except ssl.SSLCertVerificationError as exc:
        # Verification-specific failure: expired, self-signed, wrong hostname.
        return None, None, None, getattr(exc, "verify_message", "") or str(exc)
    except ssl.SSLError as exc:
        return None, None, None, str(exc)
    except socket.timeout:
        return None, None, None, "connection timed out"
    except (socket.gaierror, OSError) as exc:
        return None, None, None, str(exc)
    except Exception as exc:                       # pragma: no cover - belt and braces
        return None, None, None, str(exc)


def inspect_certificate(hostname: str, port: int = 443, timeout: int = CERT_TIMEOUT) -> dict:
    """
    Fetch and evaluate the TLS certificate served by `hostname`.

    Returns the dict described in _empty_result(), with status:
      "ok"          - a certificate was retrieved and parsed
      "unreachable" - the TCP/TLS port never answered
      "no_tls"      - it answered but no certificate could be obtained
      "error"       - anything unexpected (message in "error")

    Never raises.
    """
    if not hostname:
        return _empty_result(STATUS_ERROR, "no hostname to inspect")

    # ----- Pass 1: strict, verifying handshake -----------------------------
    # Success here proves BOTH that the chain reaches a trusted root AND that
    # the hostname matches, because create_default_context() checks both.
    der, tls_version, cipher, verify_error = _handshake(hostname, port, timeout, verify=True)
    chain_trusted = der is not None

    if der is None:
        # ----- Pass 2: permissive handshake, purely to READ the cert -------
        der, tls_version, cipher, connect_error = _handshake(
            hostname, port, timeout, verify=False
        )
        if der is None:
            # Even the permissive handshake failed: decide between "nothing is
            # listening" and "something is there but TLS did not work".
            message = connect_error or verify_error or "unknown error"
            lowered = message.lower()
            if any(
                token in lowered
                for token in (
                    "timed out", "refused", "unreachable", "getaddrinfo",
                    "name or service not known", "no such host", "failed to resolve",
                    "temporary failure in name resolution",
                )
            ):
                return _empty_result(STATUS_UNREACHABLE, message)
            return _empty_result(STATUS_NO_TLS, message)

    # ----- Parse the DER we managed to obtain ------------------------------
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        return _empty_result(STATUS_ERROR, f"could not parse certificate: {exc}")

    result = _empty_result(STATUS_OK)
    result["tls_version"] = tls_version or ""
    result["cipher"] = cipher or ""
    result["chain_trusted"] = chain_trusted

    # --- identity ---
    result["issuer_cn"] = _name_attribute(cert.issuer, NameOID.COMMON_NAME)
    result["issuer_org"] = _name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME)
    result["subject_cn"] = _name_attribute(cert.subject, NameOID.COMMON_NAME)
    result["subject_org"] = _name_attribute(cert.subject, NameOID.ORGANIZATION_NAME)

    # A certificate whose issuer equals its subject signed itself: no CA vouches
    # for it, so a browser padlock on such a site means nothing.
    result["self_signed"] = cert.issuer == cert.subject

    issuer_text = f"{result['issuer_org']} {result['issuer_cn']}".lower()
    result["is_free_ca"] = any(free_ca in issuer_text for free_ca in FREE_CA_ISSUERS)

    # --- validity window (timezone-aware throughout) ---
    now = datetime.now(timezone.utc)
    not_before = _cert_datetime(cert, "not_valid_before")
    not_after = _cert_datetime(cert, "not_valid_after")

    if not_before:
        result["valid_from"] = not_before.date().isoformat()
    if not_after:
        result["valid_to"] = not_after.date().isoformat()
        result["days_to_expiry"] = (not_after - now).days
        result["is_expired"] = not_after < now
    if not_before and not_after:
        result["validity_days"] = (not_after - not_before).days
        if not_before > now:
            # Not yet valid is just as broken as expired.
            result["is_expired"] = True

    # --- names ---
    san = _get_san_list(cert)
    result["san_count"] = len(san)
    result["san_sample"] = san[:5]
    # When pass 1 succeeded Python already validated the hostname; otherwise we
    # check it ourselves against the SAN list we just parsed.
    result["hostname_match"] = True if chain_trusted else _hostname_matches(cert, hostname)

    # --- fingerprint ---
    try:
        digest = cert.fingerprint(hashes.SHA256())
    except Exception:
        digest = hashlib.sha256(der).digest()
    result["sha256_fingerprint"] = ":".join(f"{b:02X}" for b in digest)

    if verify_error and not chain_trusted:
        result["error"] = verify_error

    return result


def resolve_ip(hostname: str) -> list[str]:
    """
    Resolve a hostname to its IP addresses.

    Returns [] on any DNS failure - a dead phishing domain must not break the
    scan. Used only for display and for the heuristic "host does not resolve"
    context, never as an ML feature.
    """
    if not hostname:
        return []
    try:
        addresses: list[str] = []
        for entry in socket.getaddrinfo(hostname, None):
            ip = entry[4][0]
            if ip not in addresses:
                addresses.append(ip)
        return addresses
    except (socket.gaierror, OSError, UnicodeError):
        return []
