"""
Stage 3: TLS
Opens a real TLS handshake against the host and inspects the certificate:
issuer, subject, validity window, SAN list, and self-signed detection.
"""
import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone


def _flatten(name_tuple):
    return dict(x[0] for x in name_tuple) if name_tuple else {}


def _probe_untrusted_cert(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """When TLS handshake fails certificate verification, probe the raw cert
    so we can still extract issuer, expiration, and self-signed status."""
    try:
        pem = ssl.get_server_certificate((hostname, port), timeout=timeout)
        fd, tmp = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        decoded = {}
        try:
            import _ssl
            if hasattr(_ssl, "_test_decode_cert"):
                decoded = _ssl._test_decode_cert(tmp)
        except Exception:
            decoded = {}
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

        issuer = _flatten(decoded.get("issuer"))
        subject = _flatten(decoded.get("subject"))
        san = [entry[1] for entry in decoded.get("subjectAltName", [])]
        days_remaining = None
        not_before = None
        not_after = None

        if "notAfter" in decoded:
            na = datetime.strptime(decoded["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_after = na.isoformat()
            days_remaining = (na - datetime.now(timezone.utc)).days
        if "notBefore" in decoded:
            nb = datetime.strptime(decoded["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_before = nb.isoformat()

        return {
            "issuer": issuer,
            "subject": subject,
            "san": san,
            "days_remaining": days_remaining,
            "not_before": not_before,
            "not_after": not_after,
            "self_signed": issuer == subject and bool(issuer),
        }
    except Exception:
        return {}


def check_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    if not hostname:
        return {"valid": False, "error": "no hostname"}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        san = [entry[1] for entry in cert.get("subjectAltName", [])]
        issuer = _flatten(cert.get("issuer"))
        subject = _flatten(cert.get("subject"))
        days_remaining = (not_after - datetime.now(timezone.utc)).days

        return {
            "valid": True,
            "issuer": issuer,
            "subject": subject,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "san": san,
            "self_signed": issuer == subject,
            "expired": days_remaining < 0,
        }
    except ssl.SSLCertVerificationError as e:
        # Handshake happened but verification failed. Probe cert details directly
        # so downstream scoring can distinguish self-signed vs expired vs invalid root.
        probe = _probe_untrusted_cert(hostname, port=port, timeout=timeout)
        verify_msg = getattr(e, "verify_message", "") or str(e)
        code = getattr(e, "verify_code", None)
        err_lower = verify_msg.lower()

        is_expired = (
            probe.get("days_remaining") is not None and probe["days_remaining"] < 0
            or code == 10
            or "expired" in err_lower
        )
        is_self_signed = (
            probe.get("self_signed", False)
            or code in (18, 19)
            or "self-signed" in err_lower
            or "self signed" in err_lower
        )

        return {
            "valid": False,
            "reachable": True,
            "error": f"certificate verification failed: {verify_msg}",
            "self_signed": is_self_signed,
            "expired": is_expired,
            "days_remaining": probe.get("days_remaining"),
            "issuer": probe.get("issuer", {}),
            "subject": probe.get("subject", {}),
            "not_before": probe.get("not_before"),
            "not_after": probe.get("not_after"),
            "san": probe.get("san", []),
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        # Couldn't reach host (network/DNS/firewall) — not a certificate issue
        return {"valid": False, "reachable": False, "error": f"connection failed: {e}"}
    except Exception as e:
        return {"valid": False, "reachable": False, "error": str(e)}


if __name__ == "__main__":
    import json
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(check_tls(host), indent=2))
