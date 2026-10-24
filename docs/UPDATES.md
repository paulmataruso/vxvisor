# VXVisor update system — end to end

This document explains how VXVisor updates itself, from a code change to a running
server and its connected desktop clients. It is the authoritative reference for the
whole flow; read it before touching anything under the "Code map" below.

## The shape of it (two tiers)

```
   you (+ Claude) push code ──▶ GitHub Release (assets: vdxd + clients + SHA256SUMS)
                                      │
             (admin clicks Check, manual)  ▼
   ┌───────────────────────────────────────────────┐
   │  vdxd server  ── Tier 2: self-update from GitHub │
   │   • /update page: Check → Apply & Restart        │
   │   • swaps its own binary (keeps .bak), restarts  │
   │   • refreshes the bundled desktop-client builds  │
   └───────────────────────────────────────────────┘
                                      │
          (client asks its own server on launch)  ▼
   ┌───────────────────────────────────────────────┐
   │  desktop client ── Tier 1: self-update from the  │
   │   server it is connected to (never from GitHub)  │
   │   • on launch: GET /clients/latest               │
   │   • if newer: prompt → download → verify → relaunch │
   └───────────────────────────────────────────────┘
```

- **Tier 2 (server ← GitHub):** only an **admin**, only on an **explicit click**.
  This is the *only* place anything in VXVisor reaches the public internet, and it
  sends nothing about the install — it honors the project's "no outbound/telemetry"
  rule by construction (see CLAUDE.md hard constraints).
- **Tier 1 (client ← its server):** automatic check on launch, but only against the
  server the user already logged into. Clients never contact GitHub. A server on the
  Preview channel serves preview client binaries; a Stable server serves stable ones.

## Versioning

- One **unified product version** per release, string form `vX.Y.Z-YYYYMMDD`
  (e.g. `v1.75.0-20261024`). The **git tag == the build version == the version
  baked into every binary** in that release. This makes comparisons unambiguous.
- Comparison parses `v?MAJOR.MINOR.PATCH-DATE` into `[major, minor, patch, date]`
  and compares lexically (`platform.VersionLess`, and the client's `versionNewer`).
- History note: vdxd and the desktop client used to have *separate* version lines
  (vdxd 1.73.x, client 1.14.x). They were **unified at 1.74.0** when the single-release
  model landed, so the client line jumped 1.14 → 1.74. Keep them unified going forward.

## Tier 1 — desktop client self-update (from its server)

**Server endpoints** (`internal/web/clients_handlers.go`, served to the client's
`vdx_session` cookie):
- `GET /clients/latest?os=<goos>&arch=<goarch>` → JSON
  `{version, filename, url, sha256, size}` for the newest matching `vxconsole-*`
  build in `<DataDir>/clients`. Empty strings if none.
- `GET /clients/download/{name}` → streams the binary.

**Client** (`desktop/internal/`):
- `client.LatestClient(goos, goarch)` and `client.DownloadTo(urlPath, w)` (hashes
  while streaming) in `client/client.go`.
- `ui/update.go`: `sh.checkForUpdate()` runs in a goroutine after the shell loads
  (`shell.go` `showShell` → `go sh.checkForUpdate()`). If `versionNewer(latest, Version)`
  it shows a confirm dialog → downloads to `<exe>.new` → verifies sha256 → `applyUpdate`.
- `ui/update_apply_{linux,windows,other}.go` (build-tagged):
  - **linux:** `chmod 0755`, rename over the running exe, `syscall.Exec` to relaunch.
  - **windows:** rename running exe → `.old`, move new in, start it, `os.Exit(0)`;
    the leftover `.old` is deleted on next launch (`cleanupOldBinary()` in `ui.New`).
  - **other:** unsupported (reports an error, app keeps running).
- The login screen shows the running version under "Management Console"
  (`ui/app.go`, from `ui.Version`) — the quickest way to confirm what you're on.

> **Client is now Wails (pivoted 2026-10-24).** The desktop client is no longer a Fyne app
> that implements each page; it is a thin **Wails** webview shell (`desktop/`, module
> `vxconsole`) that navigates to the server and renders the server's own web UI. Version is
> baked straight in with `-ldflags -X main.version=<ver>` (Wails forwards it — no
> `version_gen.go` dance). The sections below about the Fyne client's in-app self-update
> (`ui/update.go`, `update_apply_*.go`) describe the **retired** client; **client-side
> self-update is not yet reimplemented in the Wails shell** (the UI lives server-side now, so
> the shell rarely changes). Until it is, update a client by downloading it from the
> `/clients` page. The **asset contract and the server←GitHub tier below are unchanged.**

## Tier 2 — server self-update (from GitHub Releases)

**Where:** admin nav → **Updates** (`/update`, `internal/web/update_handlers.go`,
`templates/update.html`).
- **Channel** selector: **Stable** or **Preview**, persisted in the `settings` table
  (key `update_channel`, default `stable`). Stable reads GitHub `/releases/latest`
  (excludes prereleases); Preview reads `/releases` and takes the newest `prerelease`
  (falling back to latest stable if there is none).
- **Check for updates** (`POST /update/check`) → the only outbound GitHub call.
- **Apply & Restart** (`POST /update/apply`): downloads the release's `vdxd` asset,
  verifies it against the release's `SHA256SUMS`, atomically swaps `/usr/local/bin/vdxd`
  (keeping `vdxd.bak`), **refreshes `<DataDir>/clients` from the release's `vxconsole-*`
  assets** (so connected clients then auto-update), and schedules
  `systemctl restart vdxd` ~1.5 s later (so the HTTP response flushes). The page polls
  `/` until the new version answers.

**Code:**
- `internal/platform/github.go` — `CheckGitHubRelease(repo, channel)`, `DownloadVerified`,
  `FetchSHA256SUMS`, `VersionLess`.
- `internal/platform/platform.go` — `ApplyUpdate(rel, binPath)` (download → verify →
  atomic swap, keeps `.bak`), reused unchanged.
- `internal/service/update_service.go` — `CheckForUpdate`, `ApplyServerUpdate`,
  `UpdateChannel`/`SetUpdateChannel`; admin-gated + audited (`update.check/apply/channel`).
  Running version injected via `service.SetBuildVersion(version)` in `cmd/vdxd/main.go`.
- Source config: `cfg.Update.GitHubRepo` (default `paulmataruso/vxvisor`);
  `cfg.Update.FeedURL` overrides for an air-gapped JSON manifest (`platform.CheckUpdate`).

vdxd runs as **root** (`deploy/vdxd.service`), so it can overwrite its own binary and
restart the service. Restarting vdxd does **not** stop running VMs — QEMU processes are
independent and vdxd reconnects to them via QMP on startup.

## The release process

### Branch model (matches the update channels)
- **`dev`** branch → build **pre-releases** → the **Preview** channel.
- **`main`** branch → build **stable releases** → the **Stable** channel.
- Channels key off the GitHub **release type** (`prerelease: true/false`), *not* the
  branch name. The branch is just where the code and tag live.

Typical loop: develop on `dev` → publish a prerelease from `dev` → a test server set to
**Preview** pulls and verifies it → merge `dev → main` → publish a **stable** release →
Stable servers (everyone else) pick it up.

**VERSIONING RULE — Preview must always be ≥ Stable (never below).** The channels compare
by version, so a prerelease whose version is *lower* than the newest stable makes the
Preview channel look stale/backwards (and offers no upgrade to test with). Therefore:
- Every **prerelease** gets a version **strictly greater than the latest stable** (bump the
  minor ahead, e.g. stable `v1.84.0` → next preview `v1.85.0`).
- Promoting to **stable** cuts a stable release at that same version (or the next), so
  Stable catches up to Preview — then the next preview bumps above it again.
- Net: `Preview ≥ Stable` at all times; a test host on Preview always sees the build to try.
- Server self-update never downgrades (`ApplyServerUpdate` refuses a version ≤ the running
  one), so a stale Preview can't roll a host back — it just looks wrong. Keep the invariant.

### Cutting a release
`deploy/release.sh vX.Y.Z-YYYYMMDD [notes-file] [--prerelease] [--target <branch>]`
builds `vdxd` + both desktop clients at one version, writes `SHA256SUMS`, and runs
`gh release create`. Examples:
```
# preview from dev
deploy/release.sh v1.76.0-20261101 --prerelease --target dev
# stable from main
deploy/release.sh v1.76.0-20261101 --target main
```

### Asset-name contract (readers depend on these EXACT names)
```
vdxd-<ver>-linux-amd64                 # platform.findAsset("vdxd")
vxconsole-<ver>-linux-amd64            # client refresh + /clients/latest
vxconsole-<ver>-windows-amd64.exe      # client refresh + /clients/latest
SHA256SUMS                             # platform.FetchSHA256SUMS
```
`<ver>` is the tag/build version. `SHA256SUMS` lines are `"<sha256>  <assetname>"`.

### If `gh` is not installed (publish via the REST API)
The release can be created with plain `curl` + a token (what was used to bootstrap):
```
# 1) create the release (prerelease shown)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/paulmataruso/vxvisor/releases \
  -d '{"tag_name":"v1.76.0-...","target_commitish":"dev","name":"...","prerelease":true}'
# -> note the "id" in the response
# 2) upload each asset
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
  --data-binary @vdxd-v1.76.0-...-linux-amd64 \
  "https://uploads.github.com/repos/paulmataruso/vxvisor/releases/<id>/assets?name=vdxd-v1.76.0-...-linux-amd64"
# repeat for the two vxconsole assets and SHA256SUMS
```

### Repo visibility (why updates can silently show "none")
The server checks GitHub **unauthenticated**. For that to work the repo (or at least the
releases) must be **public** — `paulmataruso/vxvisor` was made public for exactly this
reason. If you ever make it private again, the Update page will report *"no published
release found"* (the API returns 404 anonymously). Alternatives if it must stay private:
give the server a GitHub token to authenticate its checks + private-asset downloads, or
publish binaries to a separate public releases repo and point `cfg.Update.GitHubRepo` at it.

## Rollback
`ApplyUpdate` keeps the previous binary as `vdxd.bak`. To roll back:
```
sudo mv /usr/local/bin/vdxd.bak /usr/local/bin/vdxd && sudo systemctl restart vdxd
```
Safe only if no new DB migration ran since (migrations are forward-only; see CLAUDE.md).

## Code map (quick index)
| Concern | File |
| --- | --- |
| Client latest/download endpoints | `internal/web/clients_handlers.go` |
| Client self-update logic | _(retired with the Fyne client; not yet reimplemented in the Wails shell)_ |
| Client shell (Wails) | `desktop/main.go`, `desktop/app.go`, `desktop/frontend/dist/index.html` |
| Client version stamp | `desktop/build.sh` → `-ldflags -X main.version=<ver>` |
| GitHub release client | `internal/platform/github.go` |
| Binary swap / feed | `internal/platform/platform.go` |
| Update service (check/apply/channel) | `internal/service/update_service.go` |
| Update web page + routes | `internal/web/update_handlers.go`, `templates/update.html`, `server.go` |
| Update nav link | `internal/web/templates/head.html` (admin, "Updates", `#i-download`) |
| Release build+publish | `deploy/release.sh` |
| Update config | `internal/config/config.go` (`UpdateConfig`) |

## Troubleshooting
- **Update page says "no published release found":** no release on the selected
  channel (Stable has no non-prerelease yet), or the repo is private (anon 404), or the
  host has no egress to api.github.com.
- **Client never prompts:** it predates v1.13.0 (no check code) — download once by hand;
  or it already matches the server's latest; or the check hit an error (silent) — check
  the login-screen version line to see what it actually is.
- **Client prompts every launch:** the `main.version` clobber bug (fixed; see Tier 1).
- **First release to point at:** until `deploy/release.sh` (or the REST steps) has run at
  least once, Tier 2 has nothing to find.
