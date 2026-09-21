# Building from Source

## Console Proxy

To run only the proxy without the system tray interface, basic installation is sufficient:

```bash
pip install -e .
swift-proxy
```

## Tray Application by OS

### Windows 7/10+

```bash
pip install -e .
swift-proxy --tray
```

### macOS

Requires a Python build with Tk support. You can verify it with the command `python3 -m tkinter`.

```bash
pip install -e .
swift-proxy --tray
```

### Linux

```bash
pip install -e .
swift-proxy --tray
```

## Console Mode from Source

```bash
swift-proxy [--port PORT] [--host HOST] [--dc-ip DC:IP ...] [-v]
```

**Arguments:**

| Argument | Default | Description |
|---|---|---|
| `--port` | `1443` | Proxy port |
| `--host` | `127.0.0.1` | Proxy host |
| `--secret` | `random` | 32-character hex key for client authorization |
| `--dc-ip` | `2:149.154.167.220`, `4:149.154.167.220` | Target IP for DC (can be specified multiple times) |
| `--no-cfproxy` | `false` | Disable [Cloudflare proxying](./CfProxy.md) attempts |
| `--cfproxy-domain` | | Specify your own domain for Cloudflare proxying [Learn more](./CfProxy.md). Can be specified multiple times. |
| `--cfproxy-worker-domain` | | Cloudflare Worker domain [Learn more](./CfWorker.md). Can be specified multiple times. |
| `--fake-tls-domain` | | Enable Fake TLS masquerading (ee-secret) with specified SNI domain |
| `--proxy-protocol` | disabled | Accept HAProxy PROXY protocol v1 (for use behind nginx/haproxy with `proxy_protocol on`) |
| `--buf-kb` | `256` | Buffer size in KB |
| `--pool-size` | `4` | Number of pre-allocated connections per DC |
| `--log-file` | disabled | Path to file for saving logs |
| `--log-max-mb` | `5` | Maximum log file size in MB (afterwards overwrites) |
| `--log-backups` | `0` | Number of log backups after overwrite |
| `-v`, `--verbose` | disabled | Verbose logging (DEBUG) |

**Examples:**

```bash
# Standard startup
swift-proxy

# Different port and additional DCs
swift-proxy --port 9050 --dc-ip 1:149.154.175.205 --dc-ip 2:149.154.167.220

# With verbose logging
swift-proxy -v

# Fake TLS masquerading (ee-secret)
swift-proxy --fake-tls-domain example.com
```
