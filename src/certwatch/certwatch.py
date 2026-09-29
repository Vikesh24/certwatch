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
            expiry_date = datetime.strptime(peer_cert.get("notAfter"), DATE_PATTERN).replace(tzinfo=timezone.utc)
            days_from_expiry = expiry_date - TODAY
    
            return {
                "return_code": 0,
                "data": {
                    "expiry_date": datetime.strftime(expiry_date, "%b %d %H:%M:%S %Y %Z"), 
                    "days_from_expiry": days_from_expiry.days
                }
            }
    except OSError as e:
        return {
            "return_code": 1,
            "data": e
        }