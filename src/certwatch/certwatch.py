import socket
import ssl
from datetime import datetime, timezone

DATE_PATTERN = "%b %-d %H:%M:%S %Y %Z"
TODAY = datetime.now(tz=timezone.utc)


def get_cert_validity(hostname: str, port: int = 443):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port)) as sock, context.wrap_socket(
            sock, server_hostname=hostname
        ) as ssock:
            peer_cert = ssock.getpeercert()
            expiry_date = datetime.strptime(
                peer_cert.get("notAfter"), DATE_PATTERN
            ).replace(tzinfo=timezone.utc)

            for data in peer_cert.get("issuer"):
                if data[0][0] == "commonName":
                    cert_issuer = data[0][1]

            days_from_expiry = expiry_date - TODAY

            return {
                "return_code": 0,
                "data": {
                    "expiry_date": expiry_date.isoformat(),
                    "days_from_expiry": days_from_expiry.days,
                    "cert_issuer": cert_issuer,
                },
            }
    except ssl.SSLCertVerificationError:
        return {"return_code": 1, "data": {"error": "TLS_failure"}}
    except TimeoutError:
        return {"return_code": 1, "data": {"error": "connection_timeout"}}
    except OSError:
        return {"return_code": 1, "data": {"error": "dns_failure"}}
