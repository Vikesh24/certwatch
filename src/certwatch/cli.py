import argparse
import sys
from string import Template

from .certwatch import get_cert_validity

SUMMARY_TEMPLATE = Template("""
host:      $host_name
port:      $port
issuer:    $cert_issuer
not_after: $expiry_date
days_left: $days_from_expiry
""")


def main():
    parser = argparse.ArgumentParser(
        description="Cli to check the SSL/TLS certificate validity",
    )
    parser.add_argument("hostname", type=str)
    parser.add_argument("--port", "-p", type=int, default=443)
    args = parser.parse_args()

    cert_data = get_cert_validity(args.hostname, args.port)

    if not cert_data["return_code"]:

        days_from_expiry = cert_data["data"]["days_from_expiry"]
        expiry_date = cert_data["data"]["expiry_date"]
        # cert_issuer = "Vikesh Certissue"
        cert_issuer = cert_data["data"]["cert_issuer"]
        print(
            SUMMARY_TEMPLATE.substitute(
                host_name=args.hostname,
                port=args.port,
                cert_issuer=cert_issuer,
                expiry_date=expiry_date,
                days_from_expiry=days_from_expiry,
            )
        )

    else:
        print(f"error: {cert_data["data"]["error"]}")
        sys.exit(1)