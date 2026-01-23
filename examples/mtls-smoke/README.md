# mTLS Smoke Test

Manual smoke test for validating SPIFFE Workload API client behavior, certificate rotation, and mTLS connectivity.

## Purpose

This smoke test validates:
- **Workload API connectivity**: Client successfully connects to SPIRE Agent via Unix domain socket
- **Certificate rotation**: SVIDs are automatically refreshed as they rotate
- **Reconnection behavior**: Client reconnects after SPIRE Agent restarts
- **mTLS authorization**: Server accepts connections only from authorized SPIFFE IDs

## Prerequisites

1. **SPIRE Agent running**: A SPIRE Agent must be running and accessible
2. **Environment variable**: `SPIFFE_ENDPOINT_SOCKET` must be set to the agent's Unix domain socket path
   ```bash
   export SPIFFE_ENDPOINT_SOCKET=/tmp/agent.sock
   ```
3. **Dependencies installed**: Both `spiffe` and `spiffetls` packages must be installed
   ```bash
   pip install spiffe spiffetls
   ```
4. **Workload registration**: Your workload must be registered with SPIRE Server and assigned a SPIFFE ID

## Usage

### Start the Server

In one terminal, start the server:

```bash
python examples/mtls-smoke/server.py --host 127.0.0.1 --port 8443
```

The server will:
- Listen for mTLS connections on the specified address
- Authorize clients matching the server's own SPIFFE ID (use `--authorize <spiffe-id>` to customize)
- Print SVID serial numbers every 20 seconds to show certificate rotation

### Start the Client

In another terminal, start the client:

```bash
python examples/mtls-smoke/client.py --host 127.0.0.1 --port 8443 --path /health --interval 5.0 --timeout 5.0
```

The client will:
- Connect to the server every `--interval` seconds
- Use `--timeout` for request timeouts
- Print request status and current SVID serial number
- Continue until interrupted (Ctrl+C)

### Debug Output

Both server and client support a `--debug` flag for verbose output:

```bash
python examples/mtls-smoke/server.py --debug
python examples/mtls-smoke/client.py --debug
```

When `--debug` is enabled:
- Full exception tracebacks are printed on errors
- Python logging is set to DEBUG level

### Test Reconnection

To validate reconnection behavior:

1. Start both server and client
2. Restart the SPIRE Agent
3. Observe that the client reconnects automatically once the agent is available again

## Expected Output

### Server Output

```
[server] listening on https://127.0.0.1:8443/health
[server] authorize: spiffe://example.org/myservice
[server] svid serial=0x1234... not_after=2024-01-01 12:00:00
[server] svid serial=0x5678... not_after=2024-01-01 12:05:00
```

### Client Output

```
[client] target=https://127.0.0.1:8443/health
[client] ok HTTP/1.1 200 OK body=ok svid_serial=0x1234...
[client] ok HTTP/1.1 200 OK body=ok svid_serial=0x5678...
```

## Troubleshooting

### "Error fetching X.509 SVID: ..."

- **Check SPIRE Agent**: Ensure the agent is running and accessible
- **Check socket path**: Verify `SPIFFE_ENDPOINT_SOCKET` points to the correct socket file
- **Check workload registration**: Ensure your workload is registered with SPIRE Server

### "TLS connection failed" or authorization errors

Common symptoms:
- `certificate verify failed` on server
- `tlsv1 alert internal error` on client

Likely causes:
- **SPIFFE ID mismatch**: The client's SPIFFE ID doesn't match the server's `--authorize` policy. Check both IDs and ensure they match.
- **Certificate validity**: Ensure certificates haven't expired
- **Trust bundles**: Verify trust bundles are properly configured

To diagnose:
- Use `--debug` flag on both server and client for detailed error information
- Check server output for the authorized SPIFFE ID
- Verify client's SPIFFE ID matches the server's authorization policy

### Server/client won't start

- **Check dependencies**: Ensure `spiffe` and `spiffetls` are installed
- **Check Python version**: Requires Python 3.10 or later
- **Check permissions**: Ensure socket file is readable/writable

