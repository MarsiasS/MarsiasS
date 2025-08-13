#!/usr/bin/env python3

import argparse
import socket
import ssl
import sys
import json
import re
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

CRLF = b"\r\n"


def recv_line(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        data += ch
        if data.endswith(CRLF):
            break
    return bytes(data)


def recv_until_dot_crlf(sock: socket.socket, timeout: float, max_bytes: int = 1024 * 1024) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        line = recv_line(sock, timeout)
        if not line:
            break
        data += line
        if data.endswith(b"." + CRLF):
            break
        if len(data) > max_bytes:
            raise RuntimeError("Server response exceeded safe limit")
    return bytes(data)


def send_cmd(sock: socket.socket, cmd: str, timeout: float) -> bytes:
    message = (cmd + "\r\n").encode("ascii", errors="ignore")
    sock.settimeout(timeout)
    sock.sendall(message)
    return recv_line(sock, timeout)


def pop3_connect_plain(host: str, port: int, timeout: float) -> Tuple[Optional[socket.socket], Optional[str]]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        banner = recv_line(sock, timeout)
        return sock, banner.decode(errors="ignore").strip()
    except Exception as e:
        return None, f"connect_error: {e}"


def pop3_capa(sock: socket.socket, timeout: float) -> Tuple[bool, List[str], str]:
    try:
        resp = send_cmd(sock, "CAPA", timeout)
        status_ok = resp.startswith(b"+OK")
        if not status_ok:
            return False, [], resp.decode(errors="ignore").strip()
        body = recv_until_dot_crlf(sock, timeout)
        lines = body.decode(errors="ignore").splitlines()
        # Remove trailing '.' and any leading response codes
        capabilities = [l.strip() for l in lines if l.strip() and l.strip() != "."]
        return True, capabilities, "+OK"
    except Exception as e:
        return False, [], f"capa_error: {e}"


def try_starttls(sock: socket.socket, host: str, timeout: float) -> Tuple[Optional[ssl.SSLSocket], str]:
    try:
        resp = send_cmd(sock, "STLS", timeout)
        if not resp.startswith(b"+OK"):
            return None, resp.decode(errors="ignore").strip()
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(sock, server_hostname=host)
        # After TLS, try a simple STAT to ensure command works
        send_cmd(tls_sock, "STAT", timeout)
        return tls_sock, "+OK"
    except ssl.SSLError as e:
        return None, f"tls_error: {e}"
    except Exception as e:
        return None, f"stls_error: {e}"


def connect_tls(host: str, port: int, timeout: float) -> Tuple[Optional[ssl.SSLSocket], str]:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        banner = recv_line(raw, timeout)  # some servers send banner after TLS, most before; we ignore errors
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(raw, server_hostname=host)
        return tls_sock, banner.decode(errors="ignore").strip()
    except Exception as e:
        return None, f"connect_tls_error: {e}"


def get_tls_info(tls_sock: ssl.SSLSocket, host: str) -> Dict[str, Any]:
    cipher = tls_sock.cipher()
    version = tls_sock.version()
    peercert = tls_sock.getpeercert()
    der_cert = None
    try:
        der_cert = tls_sock.getpeercert(binary_form=True)
    except Exception:
        pass

    issues: List[str] = []

    # Version checks
    weak_versions = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    tls_version_issue = None
    if version in weak_versions:
        tls_version_issue = f"Weak TLS protocol negotiated: {version}"
        issues.append(tls_version_issue)

    # Certificate checks
    cert_subject = None
    cert_issuer = None
    not_before = None
    not_after = None
    san_list: List[str] = []

    if peercert:
        cert_subject = peercert.get("subject")
        cert_issuer = peercert.get("issuer")
        # Expiration
        try:
            not_after_str = peercert.get("notAfter")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.utcnow():
                    issues.append("Certificate expired")
                elif not_after < datetime.utcnow() + timedelta(days=30):
                    issues.append("Certificate expires within 30 days")
        except Exception:
            pass
        # SubjectAltName / Hostname match (best-effort)
        try:
            for typ, name in peercert.get("subjectAltName", []):
                if typ == "DNS":
                    san_list.append(name)
            if san_list:
                if not _hostname_matches(host, san_list):
                    issues.append("Certificate SAN does not match host")
        except Exception:
            pass
        # Signature algorithm (weak if SHA1/MD5)
        if der_cert is not None:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
                if sig_algo in {"md5", "sha1"}:
                    issues.append(f"Weak certificate signature algorithm: {sig_algo}")
            except Exception:
                # cryptography may not be installed; ignore
                pass

    return {
        "tls_version": version,
        "cipher": cipher,
        "cert_subject": cert_subject,
        "cert_issuer": cert_issuer,
        "not_after": not_after.isoformat() + "Z" if isinstance(not_after, datetime) else None,
        "sans": san_list,
        "issues": issues,
    }


def _hostname_matches(host: str, dns_names: List[str]) -> bool:
    host = host.lower()
    for pattern in dns_names:
        pattern = pattern.lower()
        if pattern == host:
            return True
        # Wildcard match for one label only
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) and host.count('.') >= suffix.count('.') + 1:
                return True
    return False


def try_plain_auth_without_tls(sock: socket.socket, timeout: float) -> Tuple[bool, str, List[str]]:
    findings: List[str] = []
    try:
        resp = send_cmd(sock, "USER invalid_user_scanner", timeout)
        if resp.startswith(b"-ERR") and b"STLS" in resp.upper():
            return False, resp.decode(errors="ignore").strip(), findings
        # If server allows proceeding to PASS without requiring STLS, this indicates plaintext auth is possible
        resp2 = send_cmd(sock, "PASS invalid_password_scanner", timeout)
        if resp2.startswith(b"-ERR") and b"STLS" in resp2.upper():
            return False, resp2.decode(errors="ignore").strip(), findings
        # If server responds with +OK or generic -ERR without referencing STLS requirement, consider plaintext allowed
        findings.append("Server permits USER/PASS before TLS (plaintext credentials could be exposed)")
        return True, resp2.decode(errors="ignore").strip(), findings
    except Exception as e:
        return False, f"auth_error: {e}", findings


def test_supported_tls_versions(host: str, port: int, timeout: float) -> Dict[str, Any]:
    results: Dict[str, Any] = {"TLSv1": None, "TLSv1.1": None, "TLSv1.2": None, "TLSv1.3": None}
    versions = [
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    for name, v in versions:
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            context = ssl.create_default_context()
            context.minimum_version = v
            context.maximum_version = v
            tls_sock = context.wrap_socket(raw, server_hostname=host)
            results[name] = True
            try:
                tls_sock.close()
            except Exception:
                pass
        except ssl.SSLError:
            results[name] = False
        except Exception:
            results[name] = False
    return results


def extract_software_from_banner(banner: Optional[str]) -> Optional[str]:
    if not banner:
        return None
    # Heuristic patterns for common servers (Dovecot, Courier, Cyrus, etc.)
    patterns = [
        r"dovecot[ /-]?([0-9.]+)?",
        r"courier[- ]imap[- ]([0-9.]+)?",
        r"courier[- ]pop3[- ]([0-9.]+)?",
        r"cyrus[ -]imapd[ /-]?([0-9.]+)?",
        r"uw[- ]imap[ /-]?([0-9.]+)?",
        r"qpopper[ /-]?([0-9.]+)?",
        r"(Microsoft Exchange)[ /-]?([0-9.]+)?",
    ]
    lower = banner.lower()
    for pat in patterns:
        m = re.search(pat, lower)
        if m:
            return m.group(0)
    return None


def assess_best_practices(
    host: str,
    banner: Optional[str],
    capabilities: Optional[List[str]],
    plaintext_auth_allowed: bool,
    tls_info_direct: Optional[Dict[str, Any]],
    tls_info_starttls: Optional[Dict[str, Any]],
    supported_versions_direct: Optional[Dict[str, Any]],
    supported_versions_starttls: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    def add(severity: str, title: str, detail: Optional[str] = None):
        entry = {"severity": severity, "title": title}
        if detail:
            entry["detail"] = detail
        findings.append(entry)

    # Banner exposure
    software = extract_software_from_banner(banner)
    if software:
        add("info", "Server banner reveals software/version", software)

    # CAPA checks
    if capabilities is not None:
        capa_upper = [c.upper() for c in capabilities]
        if capabilities:
            if "STLS" not in capa_upper:
                add("medium", "Server CAPA does not advertise STLS (STARTTLS)")
            if any(c.startswith("APOP") or c == "APOP" for c in capa_upper):
                add("low", "APOP supported (MD5-based; considered deprecated)")
        else:
            add("low", "Server does not support CAPA or refused CAPA command")

    # Plaintext authentication
    if plaintext_auth_allowed:
        add("high", "Plaintext authentication allowed on port 110")

    # TLS info
    def check_tls_info(source: str, info: Optional[Dict[str, Any]]):
        if not info:
            return
        for issue in info.get("issues", []) or []:
            sev = "medium"
            if "expired" in issue.lower() or "weak" in issue.lower():
                sev = "high" if "expired" in issue.lower() else "medium"
            add(sev, f"TLS issue via {source}", issue)

    check_tls_info("pop3s", tls_info_direct)
    check_tls_info("starttls", tls_info_starttls)

    # Weak protocol support
    def check_supported_versions(source: str, support: Optional[Dict[str, Any]]):
        if not support:
            return
        for weak in ["TLSv1", "TLSv1.1"]:
            val = support.get(weak)
            if val is True:
                add("medium", f"{source} allows deprecated protocol {weak}")

    check_supported_versions("pop3s", supported_versions_direct)
    check_supported_versions("starttls", supported_versions_starttls)

    # Prefer encrypted-only ports
    if plaintext_auth_allowed:
        add("medium", "Enforce TLS 1.2+ and disable cleartext logins on 110")

    return findings


def scan_host(host: str, timeout: float, scan_ports: List[int]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "host": host,
        "ports": {},
        "findings": [],
    }

    capabilities_110: Optional[List[str]] = None
    banner_110: Optional[str] = None
    plaintext_auth_allowed = False

    if 110 in scan_ports:
        sock110, banner = pop3_connect_plain(host, 110, timeout)
        banner_110 = banner if sock110 else None
        port_info: Dict[str, Any] = {
            "banner": banner,
            "capa": None,
            "starttls": None,
            "errors": None,
        }
        if not sock110:
            port_info["errors"] = banner
            result["ports"]["110"] = port_info
        else:
            try:
                ok, caps, note = pop3_capa(sock110, timeout)
                port_info["capa"] = caps if ok else note
                capabilities_110 = caps if ok else []
                # Test plaintext auth before TLS
                allowed, auth_note, auth_findings = try_plain_auth_without_tls(sock110, timeout)
                plaintext_auth_allowed = allowed
                if auth_findings:
                    port_info.setdefault("notes", []).extend(auth_findings)
                # Try STARTTLS
                tls_sock, tls_note = try_starttls(sock110, host, timeout)
                if tls_sock:
                    tls_details = get_tls_info(tls_sock, host)
                    port_info["starttls"] = {"tls": tls_details}
                    try:
                        tls_sock.close()
                    except Exception:
                        pass
                else:
                    port_info["starttls"] = {"error": tls_note}
            except Exception as e:
                port_info["errors"] = f"port110_error: {e}"
            finally:
                try:
                    sock110.close()
                except Exception:
                    pass
            result["ports"]["110"] = port_info

    tls_info_direct = None
    supported_versions_direct = None
    if 995 in scan_ports:
        tls_sock995, banner995 = connect_tls(host, 995, timeout)
        port_info_tls: Dict[str, Any] = {
            "banner": banner995,
            "errors": None,
        }
        if tls_sock995:
            try:
                tls_info_direct = get_tls_info(tls_sock995, host)
                port_info_tls["tls"] = tls_info_direct
            except Exception as e:
                port_info_tls["errors"] = f"tls995_info_error: {e}"
            finally:
                try:
                    tls_sock995.close()
                except Exception:
                    pass
        else:
            port_info_tls["errors"] = banner995
        result["ports"]["995"] = port_info_tls

    # Protocol support probing (non-intrusive)
    if 995 in scan_ports:
        try:
            supported_versions_direct = test_supported_tls_versions(host, 995, timeout)
        except Exception:
            supported_versions_direct = None
    supported_versions_starttls = None
    if 110 in scan_ports:
        try:
            # For STARTTLS, we cannot easily probe without issuing STLS first.
            # We will attempt a direct TCP connect, then STARTTLS, then measure version only via negotiated info above.
            supported_versions_starttls = None
        except Exception:
            supported_versions_starttls = None

    # Findings aggregation
    tls_info_starttls = None
    if 110 in result["ports"] and isinstance(result["ports"]["110"].get("starttls"), dict):
        tls_info_starttls = result["ports"]["110"]["starttls"].get("tls")

    findings = assess_best_practices(
        host=host,
        banner=banner_110,
        capabilities=capabilities_110,
        plaintext_auth_allowed=plaintext_auth_allowed,
        tls_info_direct=tls_info_direct,
        tls_info_starttls=tls_info_starttls,
        supported_versions_direct=supported_versions_direct,
        supported_versions_starttls=supported_versions_starttls,
    )
    result["findings"] = findings

    return result


def main():
    parser = argparse.ArgumentParser(
        description="POP3 security scanner (best-practice checks). Performs safe, non-destructive tests.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("host", help="Target hostname or IP")
    parser.add_argument("--ports", default="110,995", help="Comma-separated ports to scan")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output JSON report")

    args = parser.parse_args()

    try:
        ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})
    except ValueError:
        print("Invalid --ports. Must be integers separated by commas.", file=sys.stderr)
        sys.exit(2)

    report = scan_host(args.host, args.timeout, ports)

    if args.as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"Host: {report['host']}")
        for port, info in report["ports"].items():
            print(f"\nPort {port}:")
            banner = info.get("banner")
            if banner:
                print(f"  Banner: {banner}")
            errors = info.get("errors")
            if errors:
                print(f"  Errors: {errors}")
            capa = info.get("capa")
            if capa is not None:
                if isinstance(capa, list):
                    caps = ", ".join(capa)
                else:
                    caps = str(capa)
                print(f"  CAPA: {caps}")
            if info.get("starttls"):
                st = info["starttls"]
                if "error" in st:
                    print(f"  STARTTLS: {st['error']}")
                else:
                    tls = st.get("tls") or {}
                    print("  STARTTLS: negotiated")
                    print(f"    TLS: {tls.get('tls_version')} cipher={tls.get('cipher')}")
                    if tls.get("issues"):
                        for iss in tls["issues"]:
                            print(f"    Issue: {iss}")
            if info.get("tls"):
                tls = info.get("tls")
                print(f"  TLS: {tls.get('tls_version')} cipher={tls.get('cipher')}")
                if tls.get("issues"):
                    for iss in tls["issues"]:
                        print(f"    Issue: {iss}")
        if report.get("findings"):
            print("\nFindings:")
            for f in report["findings"]:
                sev = f.get("severity")
                title = f.get("title")
                detail = f.get("detail")
                if detail:
                    print(f"- [{sev}] {title}: {detail}")
                else:
                    print(f"- [{sev}] {title}")


if __name__ == "__main__":
    main()