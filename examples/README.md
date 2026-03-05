# Examples

The repo includes manual smoke tests exposed as `uv` entry points. They are not
part of CI and are not production examples.

Available commands:

```bash
uv run --package py-spiffe-examples mtls-smoke-server --host 127.0.0.1 --port 8443
uv run --package py-spiffe-examples mtls-smoke-client --host 127.0.0.1 --port 8443
uv run --package py-spiffe-examples httpx-stdlib-mtls-client --host 127.0.0.1 --port 8443
```

`mtls-smoke-server` and `mtls-smoke-client` validate:
- Workload API connectivity
- X.509 SVID rotation
- reconnect behavior after SPIRE Agent restarts
- mTLS authorization

`httpx-stdlib-mtls-client` validates:
- `SpiffeSSLContext` integration with `httpx`
- stdlib TLS compatibility
- certificate refresh behavior

Prerequisites:
- SPIRE Agent running and reachable
- `SPIFFE_ENDPOINT_SOCKET` set to the Workload API socket
- workload registration configured in SPIRE

Typical flow:

```bash
export SPIFFE_ENDPOINT_SOCKET=/tmp/agent.sock
uv run --package py-spiffe-examples mtls-smoke-server --host 127.0.0.1 --port 8443
uv run --package py-spiffe-examples mtls-smoke-client --host 127.0.0.1 --port 8443 --path /health
uv run --package py-spiffe-examples httpx-stdlib-mtls-client --host 127.0.0.1 --port 8443 --path /health
```

Useful flags:
- `--debug` for verbose tracebacks
- `--authorize <spiffe-id>` on `mtls-smoke-server` to override the default
  self-authorization policy
- `--interval`, `--timeout`, and `--source-timeout` on the clients to tune
  polling and startup behavior

Common failure modes:
- Workload API fetch failures usually mean the agent is unavailable, the socket
  path is wrong, or the workload is not registered correctly.
- TLS verification failures usually mean the presented SPIFFE ID does not match
  the server authorization policy or the trust bundle is not configured the way
  you expect.
