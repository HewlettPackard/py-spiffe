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

Manual mTLS smoke test server. Not intended for production use.
"""

import argparse
import logging
import signal
import sys
import threading
import time
import traceback

from spiffe import SpiffeId, X509Source
from spiffetls import ListenOptions, listen
from spiffetls.mode import ServerTlsMode
import spiffetls.tlsconfig.authorize


def log_error(prefix, err, debug):
    """Log error with optional traceback."""
    print(f"{prefix}: {type(err).__name__}: {err}", file=sys.stderr)
    if debug:
        traceback.print_exception(type(err), err, err.__traceback__)


def handle_request(conn, addr, debug=False):
    """Handle a single client request with bounded HTTP parsing."""
    try:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 64 * 1024:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        body = b"ok\n"
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            + body
        )
        conn.sendall(resp)
    except Exception as e:
        log_error(f"[server] request error from {addr}", e, debug)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve_loop(sock, stop_event, debug=False):
    """Accept connections and handle requests until stop_event is set."""
    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
            handle_request(conn, addr, debug)
        except Exception as e:
            if not stop_event.is_set():
                log_error("[server] accept error", e, debug)
                time.sleep(0.2)
        except KeyboardInterrupt:
            break


def main():
    parser = argparse.ArgumentParser(
        description="mTLS smoke test server for SPIFFE Workload API validation"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Server host address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8443, help="Server port (default: 8443)"
    )
    parser.add_argument(
        "--authorize",
        default="self",
        help="Authorization policy: 'self' (match server's SPIFFE ID) or a full SPIFFE ID (default: self)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output including full tracebacks",
    )
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    x509_source = None
    sock = None
    stop_event = threading.Event()

    def signal_handler(sig, frame):
        print("\n[server] shutdown signal received", file=sys.stderr)
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        x509_source = X509Source(timeout_in_seconds=30)

        if args.authorize == "self":
            allowed_id = x509_source.svid.spiffe_id
        else:
            allowed_id = SpiffeId(args.authorize)

        options = ListenOptions(
            tls_mode=ServerTlsMode.MTLS,
            authorize_fn=spiffetls.tlsconfig.authorize.authorize_id(allowed_id),
        )

        addr = f"{args.host}:{args.port}"
        sock = listen(addr, x509_source, options)
        print(f"[server] listening on https://{addr}/health")
        print(f"[server] authorize: {allowed_id}")

        server_thread = threading.Thread(
            target=serve_loop, args=(sock, stop_event, args.debug), daemon=True
        )
        server_thread.start()

        while not stop_event.is_set():
            leaf = x509_source.svid.cert_chain[0]
            print(
                f"[server] svid serial={hex(leaf.serial_number)} "
                f"not_after={leaf.not_valid_after_utc}"
            )
            time.sleep(20)
    except KeyboardInterrupt:
        print("[server] shutting down...", file=sys.stderr)
    except Exception as e:
        log_error("[server] fatal error", e, args.debug)
        sys.exit(1)
    finally:
        stop_event.set()
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        if x509_source is not None:
            try:
                x509_source.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
