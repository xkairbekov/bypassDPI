# bypassDPI

A lightweight HTTP forward proxy that circumvents Deep Packet Inspection (DPI) to restore access to blocked websites — without a VPN.

---

## Quick Start
 
### Docker (recommended)
 
Bypass all proxied traffic:
 
```bash
docker run -d \
  --name bypassdpi \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/xkairbekov/bypassdpi:latest
```
 
Bypass only specific domains:
 
```bash
docker run -d \
  --name bypassdpi \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/xkairbekov/bypassdpi:latest \
  --domains youtube.com,instagram.com,x.com
```
 
### Binary
 
Download the archive for your platform from [Releases](../../releases), extract it, and run:
 
```bash
./bypassdpi --listen 127.0.0.1:8080
```

---

## Configuration
 
| Flag | Default | Description |
|---|---|---|
| `--listen` | `0.0.0.0:8080` | Address and port the proxy listens on |
| `--dns` | `1.1.1.1` | Bootstrap DNS server used to resolve the DoH endpoint. Use `system` to use the OS resolver |
| `--doh-url` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS endpoint for domain resolution. Use `disable` to turn off DoH |
| `--domains` | *(empty)* | Comma-separated list of domains to apply bypass to; if empty, bypass is applied to **all** proxied traffic |
| `--split-delay` | `0ms` | Delay between TCP fragment writes; increase if fragmentation is too fast for the destination to reassemble |
| `--max-connections` | `512` | Maximum concurrent client connections; set to `0` for no limit |
| `--log-level` | `info` | Log verbosity: `error` · `info` · `debug` |
 
Alternative public DNS-over-HTTPS (DoH) endpoints are listed at [dnsprivacy.org](https://dnsprivacy.org/public_resolvers/#dns-over-https-doh).
 
---

## Domain Matching
 
`--domains` performs **suffix matching**: a rule for `example.com` matches both the apex domain and all subdomains.
 
| Rule | Matches |
|---|---|
| `youtube.com` | `youtube.com`, `m.youtube.com`, `music.youtube.com` |
| `x.com` | `x.com`, `api.x.com` |
 
---

## Build & Run

### Using Docker

```bash
docker build -t bypassdpi .
docker run --rm -p 127.0.0.1:8080:8080 bypassdpi
```

### From Source

**Prerequisites:** Go 1.26+

```bash
go build -o bypassdpi ./cmd/bypassdpi
./bypassdpi --listen 127.0.0.1:8080
```

---

## Troubleshooting
 
**Site is still blocked**
 
- Try `--log-level=debug` to inspect what the proxy is doing.
- Some ISPs block by IP, not hostname — DPI fragmentation won't help in that case.
- Try increasing `--split-delay` (e.g. `--split-delay=2ms`).
 
---
 
## Acknowledgements
 
Inspired by prior work in the DPI circumvention space:
 
- [SpoofDPI](https://github.com/xvzc/SpoofDPI) by [@xvzc](https://github.com/xvzc)
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) by [@ValdikSS](https://github.com/ValdikSS)
 
---
 
## License
 
[MIT](LICENSE)
