# Public VDI gateway

This is the internet-facing way for users to reach their desktops: they open a
URL, sign in, see **My Desktops**, and click one — a full remote desktop opens in
the browser tab (keyboard, mouse, clipboard, audio), no client install.

## Architecture

```
        Internet (HTTPS/WSS)
              │
        ┌─────▼─────┐   TLS termination + Let's Encrypt
        │   Caddy   │   (reverse proxy)
        └─────┬─────┘
              │ HTTP (loopback)
   ┌──────────▼───────────┐          ┌───────────────┐
   │ vdxd public listener │          │ vdxd admin UI │  ← LAN / VPN only,
   │  127.0.0.1:8768      │          │ 172.16.1.67:8766 │   NOT proxied
   │  login · My Desktops │          └───────────────┘
   │  /desktop · /ws      │
   └──────────┬───────────┘
              │ (server-side)
        ┌─────▼─────┐        ┌──────────────┐
        │   guacd   │───RDP/VNC──▶│  guest VMs │  (overlay / loopback)
        │127.0.0.1:4822│        └──────────────┘
```

Two separate listeners inside one `vdxd`:

- **Admin listener** (`[server].addr`, e.g. `172.16.1.67:8766`) — the full
  management UI. Keep it on the LAN or behind a VPN. **Never** proxy it publicly.
- **Public listener** (`[public].addr`, default `127.0.0.1:8768`) — only login,
  OIDC, the **My Desktops** portal, connect/disconnect, and the desktop page +
  WebSocket. It serves no management screens at all.

`guacd`, QEMU VNC and QMP all stay bound to loopback and are never exposed.

## Security model

- **TLS/WSS** is terminated by the proxy; the public listener binds loopback so
  only the proxy reaches it.
- **Per-connection tokens.** When a user connects, the broker mints a short-lived
  (2 min) HMAC-signed token naming exactly one session + user. The desktop
  WebSocket requires either that token or the session cookie, so a leaked/guessed
  URL cannot open someone else's desktop and tokens cannot be replayed.
- **Login** is the app's own password auth or **OIDC SSO** (`[oidc]`). Pair with
  your IdP's MFA for internet exposure.
- **Idle reclaim.** Pooled desktops idle past `[broker].idle_minutes` are stopped
  and returned to the pool automatically.
- Set secure cookies and HSTS at the proxy (examples below).

## Caddy (recommended — automatic HTTPS)

`/etc/caddy/Caddyfile`:

```caddy
desktops.example.com {
    encode zstd gzip
    # WebSocket upgrades are proxied transparently by Caddy.
    reverse_proxy 127.0.0.1:8768

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        -Server
    }
}
```

That is the whole file — Caddy obtains and renews the certificate from Let's
Encrypt automatically. Reload: `sudo systemctl reload caddy`.

## nginx alternative

```nginx
server {
    listen 443 ssl http2;
    server_name desktops.example.com;

    ssl_certificate     /etc/letsencrypt/live/desktops.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/desktops.example.com/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8768;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;      # WebSocket
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 86400s;                   # long-lived desktop sockets
    }
}
```

## vdxd config

```toml
[public]
enabled  = true
addr     = "127.0.0.1:8768"              # behind the proxy
base_url = "https://desktops.example.com"

[broker]
idle_minutes = 30                         # reclaim idle pooled desktops
# secret_file defaults to <data_dir>/broker.key (auto-created)

[gateway]
enabled  = true
protocol = "rdp"                          # vnc fallback when the guest isn't routable
```

## Operating it

1. **Admin** → *Desktop Pools*: create a pool (image, pooled/persistent, specs,
   max size), then **Grant** it to usernames.
2. Users browse to `https://desktops.example.com`, sign in, and see **My
   Desktops**; **Connect** leases/boots a desktop and opens it.
3. Pooled desktops are reclaimed on idle; users can **Disconnect** to release one
   immediately. Persistent desktops stay assigned and are only stopped.

For desktops that need true RDP device-redirection (audio in/out, microphone,
webcam, multi-monitor), run the pool on an **overlay** network so each guest gets
a routable IP and provision xrdp (cloud-init does this automatically when the
gateway protocol is `rdp` and the guest has a lease — see
[CLUSTER-NETWORKING.md](CLUSTER-NETWORKING.md)). Without that, the gateway falls
back to VNC, which still gives a full keyboard/mouse/clipboard desktop.
