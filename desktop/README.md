# VXVisor Console (desktop client)

A small, VMRC-style desktop app for **Windows and Linux** that connects to a
VXVisor host, lists its virtual machines, runs basic power operations
(start / stop / restart / delete), and opens the VM **console** — a native VNC
viewer built in, no browser required.

It is a **separate Go module** from the server so the server binary never pulls
in the GUI/OpenGL dependencies.

```
desktop/
  cmd/vxconsole/      entry point
  internal/client/    REST + login (cookie/CSRF) + console WebSocket dial   (pure Go)
  internal/rfb/       native RFB (VNC) client over the console WebSocket     (pure Go)
  internal/ui/        Fyne UI: connect -> inventory -> console               (CGO/OpenGL)
```

## How it connects

The app authenticates the same way the browser does — **host + username +
password** — captures the `vdx_session` cookie, and reuses it for everything:

- inventory via the REST API (`GET /api/v1/sessions`),
- start / stop / delete via the REST API,
- restart via the cookie-authed UI endpoint (the CSRF token is derived from the
  session cookie, exactly as the server derives it),
- the console over the authenticated WebSocket proxy (`/console/{id}/ws`), raw
  RFB, using the VM's VNC password.

No server-side changes are required.

## The console

A from-scratch RFB 3.8 client that advertises only Raw, CopyRect, Zlib and
DesktopSize encodings — QEMU honors the client's encoding list, so there is no
Tight/ZRLE to decode. Pixel format is forced to 32bpp true-colour for a trivial
decode path. The remote cursor is rendered by the server into the framebuffer.

Input: mouse (absolute), scroll wheel, printable keys, and the special keys
(arrows, function keys, Enter/Tab/Esc, etc.). Ctrl / Alt / Shift are **sticky**
one-shot modifiers (tap the toolbar button, then press the next key), plus a
dedicated **Ctrl+Alt+Del** button. Clipboard: **Paste** types the host clipboard
into the guest (works without a guest agent); **Send clipboard** pushes it to the
guest clipboard (needs a guest agent).

## Build

Builds use [`fyne-cross`](https://github.com/fyne-io/fyne-cross), which compiles
inside Docker images that carry the OpenGL / MinGW toolchains, so you do **not**
need GL headers or a Windows machine.

```bash
# one-time
go install github.com/fyne-io/fyne-cross@latest

# build both platforms (produces artifacts under fyne-cross/dist/)
./build.sh v1.0.0
```

The resulting `vxconsole` (Linux) and `vxconsole.exe` (Windows) can be dropped
into the server's `clients/` folder (inside its data directory, e.g.
`/var/lib/vdxclone/clients/`) to appear on the server's **Desktop Client**
download page.

## Run

Launch the binary, enter the host (`10.0.0.5` or `10.0.0.5:8766`), your username
and password, and connect.

> Over plain HTTP the console works on a LAN. For an encrypted link and one-click
> clipboard, front the server with a TLS reverse proxy.
