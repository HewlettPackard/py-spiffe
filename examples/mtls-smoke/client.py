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

Manual mTLS smoke test client. Not intended for production use.
"""

import argparse
import logging
import signal
import sys
import time
import traceback
import select

from OpenSSL import SSL

from spiffe import X509Source
from spiffetls import dial


def log_error(prefix, err, debug):
    """Log error with optional traceback."""
    print(f"{prefix}: {type(err).__name__}: {err}", file=sys.stderr)
    if debug:
        traceback.print_exception(type(err), err, err.__traceback__)


def send_request(conn, path="/health", timeout=5.0):
    """
    Send HTTP GET request and read response (best-effort, bounded).

    NOTE:
    spiffetls.dial() returns a pyOpenSSL Connection. Even in blocking mode,
    OpenSSL may raise WantReadError / WantWriteError while the TLS state
    machine makes progress. This smoke test uses minimal, bounded
    select()-based retries to avoid flakiness.
    """
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")

    deadline = time.time() + timeout

    def time_left():
        return max(0.0, deadline - time.time())

    # ---- Write request (handle WantRead / WantWrite) ----
    view = memoryview(request)
    while view:
        if time.time() >= deadline:
            raise TimeoutError("timeout sending request")
        try:
            sent = conn.send(view)
            view = view[sent:]
        except SSL.WantWriteError:
            _, w, _ = select.select([], [conn], [], time_left())
            if not w:
                raise TimeoutError("timeout waiting for socket writability")
        except SSL.WantReadError:
            r, _, _ = select.select([conn], [], [], time_left())
            if not r:
                raise TimeoutError("timeout waiting for socket readability")

    # ---- Read response headers (bounded) ----
    data = b""
    while len(data) < 64 * 1024:
        if time.time() >= deadline:
            raise TimeoutError("timeout reading response")
        try:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        except SSL.WantReadError:
            r, _, _ = select.select([conn], [], [], time_left())
            if not r:
                raise TimeoutError("timeout waiting for socket readability")
        except SSL.WantWriteError:
            _, w, _ = select.select([], [conn], [], time_left())
            if not w:
                raise TimeoutError("timeout waiting for socket writability")
        except SSL.ZeroReturnError:
            break

    return data


def main():
    parser = argparse.ArgumentParser(
        description="mTLS smoke test client for SPIFFE Workload API validation"
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

    stop_requested = False

    def signal_handler(sig, frame):
        nonlocal stop_requested
        print("\n[client] shutdown signal received", file=sys.stderr)
        stop_requested = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    x509_source = None

    try:
        x509_source = X509Source(timeout_in_seconds=args.source_timeout)

        target = f"https://{args.host}:{args.port}{args.path}"
        print(f"[client] target={target}")

        while not stop_requested:
            leaf = x509_source.svid.cert_chain[0]
            serial = hex(leaf.serial_number)

            conn = None
            try:
                addr = f"{args.host}:{args.port}"
                conn = dial(addr, x509_source)

                # Best-effort configuration; behavior depends on underlying object
                if hasattr(conn, "setblocking"):
                    conn.setblocking(True)

                response = send_request(conn, args.path, timeout=args.timeout)

                status_line = response.split(b"\r\n")[0].decode(
                    "ascii", errors="replace"
                )
                body_start = response.find(b"\r\n\r\n")
                body = (
                    response[body_start + 4 :].strip().decode("ascii", errors="replace")
                    if body_start >= 0
                    else ""
                )

                print(
                    f"[client] ok {status_line} body={body} svid_serial={serial}"
                )

            except Exception as e:
                log_error(f"[client] fail svid_serial={serial}", e, args.debug)
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

            if not stop_requested:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        print("[client] stopping...", file=sys.stderr)
    except Exception as e:
        log_error("[client] fatal error", e, args.debug)
        sys.exit(1)
    finally:
        if x509_source is not None:
            try:
                x509_source.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
