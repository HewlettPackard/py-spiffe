# httpx stdlib mTLS example

Manual smoke test for `SpiffeSSLContext` with `httpx` and Python's standard library TLS stack.

## Purpose

This example validates:

- Integration of `SpiffeSSLContext` with `ssl.SSLContext`
- Automatic certificate refresh during X.509 SVID rotation
- Recovery after temporary SPIRE Agent unavailability
- Compatibility with stdlib-based HTTP clients

## Scope

- Client-side only
- Manual testing only
- Not a production reference
- Not part of CI

## Prerequisites

- A SPIFFE-enabled HTTPS endpoint (for example `examples/mtls-smoke/server.py`)
- SPIRE Agent running and reachable
- `SPIFFE_ENDPOINT_SOCKET` set
- Python 3.10+
- Dependencies installed:

```bash
pip install spiffe spiffetls httpx
```

## Usage

Start the client:

```bash
python examples/httpx-stdlib-mtls/client.py --host 127.0.0.1 --port 8443 --path /health --interval 5.0 --timeout 5.0
```

The client will:
- Connect to the server every `--interval` seconds
- Use `--timeout` for request timeouts
- Print request status and current SVID serial number
- Continue until interrupted (Ctrl+C)

### Debug Output

The client supports a `--debug` flag for verbose output:

```bash
python examples/httpx-stdlib-mtls/client.py --debug
```

When `--debug` is enabled:
- Full exception tracebacks are printed on errors
- Python logging is set to DEBUG level

## Expected Output

```
[client] target=https://127.0.0.1:8443/health
[client] ok status=200 svid_serial=0x1234...
[client] ok status=200 svid_serial=0x5678...
```
