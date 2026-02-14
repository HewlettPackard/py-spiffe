"""
(C) Copyright 2021 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

Manual stdlib TLS smoke test using httpx and SpiffeSSLContext.

Validates certificate rotation and Workload API reconnection behavior
with Python's ssl.SSLContext integration.
"""

import argparse
import logging
import signal
import sys
import time
import traceback

import httpx
from spiffe import X509Source
from spiffetls import SpiffeSSLContext


def log_error(prefix, err, debug):
    """Log error with optional traceback."""
    print(f"{prefix}: {type(err).__name__}: {err}", file=sys.stderr)
    if debug:
        traceback.print_exception(type(err), err, err.__traceback__)


def main():
    parser = argparse.ArgumentParser(
        description="httpx + SpiffeSSLContext mTLS smoke test"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Server host address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8443, help="Server port (default: 8443)"
    )
    parser.add_argument(
        "--path", default="/health", help="Request path (default: /health)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Request interval in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--source-timeout",
        type=float,
        default=30.0,
        help="X509Source initialization timeout in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output including full tracebacks",
    )
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    stop = False

    def handle_signal(sig, frame):
        nonlocal stop
        stop = True
        print("\n[client] shutdown requested", file=sys.stderr)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    x509_source = None

    try:
        x509_source = X509Source(timeout_in_seconds=args.source_timeout)
        ssl_context = SpiffeSSLContext(
            x509_source,
            use_system_trusted_cas=True,
        )

        client = httpx.Client(verify=ssl_context)

        target = f"https://{args.host}:{args.port}{args.path}"
        print(f"[client] target={target}")

        while not stop:
            leaf = x509_source.svid.cert_chain[0]
            serial = hex(leaf.serial_number)

            try:
                resp = client.get(target, timeout=args.timeout)
                print(
                    f"[client] ok status={resp.status_code} "
                    f"svid_serial={serial}"
                )
            except Exception as e:
                log_error(f"[client] fail svid_serial={serial}", e, args.debug)

            if not stop:
                time.sleep(args.interval)

    finally:
        if x509_source is not None:
            x509_source.close()


if __name__ == "__main__":
    main()
