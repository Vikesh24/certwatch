import argparse

from .certwatch import get_cert_validity


def main():
    parser = argparse.ArgumentParser(
        description="Cli to check the SSL/TLS certificate validity",
    )
    parser.add_argument("hostname", type=str)
    parser.add_argument("--port", "-p", type=int, default=443)
    args = parser.parse_args()

    expiry_date, days_from_expiry = get_cert_validity(args.hostname, args.port)

    print(f"Certificate for {args.hostname} will expire in {days_from_expiry} days({expiry_date.ljust(20)})")