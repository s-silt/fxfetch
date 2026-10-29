# Android worker deployment

This directory prepares a **separate Ubuntu VM** for the fxfetch Android browser.
It provides deployment and controlled session helpers. The API must keep
Android collection disabled until the complete connection, timeout, disk and
session acceptance checks pass.

## Acceptance snapshot — 2026-10-29

The original Windows deployment passed the following synthetic checks with
Chrome/Trichrome **145.0.7632.218** (version code **763221838**). This fixed Google
SDK build is not described as the current stable Chrome. These are historical
acceptance results, not a guarantee of later runtime health or a fresh machine's
readiness. Use live capability and task results for the current deployment.

- Real Android CDP controls, same-session JS/Cookie/one-use-ticket acquisition,
  and a 13,607,818-byte APK through Workflow/JobService and the API attachment
  route passed; the three critical URLs were requested once each and hashes
  matched. The APK was synthetic and was not installed.
- Eight inner-network rejection checks, independent outer INPUT/FORWARD
  rejection checks, and the explicitly permitted broker path passed. Unpermitted
  Chrome background traffic was rejected before upstream connection.
- Cancel/restart used a different lease and container. A 210-second native
  guest lease expired without an early host `end`; the exact container was gone
  about four seconds after expiry and expired proof was rejected.
- The actual Android `/data` backing device was 2,147,483,648 bytes. A write-full
  probe returned ENOSPC and its own probe file was removed. The disk bound is
  separate from the API/build scratch soft budget.
- The original LAN service was enabled only after those checks and a live idle
  readiness check. Production target collection still validates each new lease;
  a configured file or a cached capability response does not grant a lease.

The latest source-wide and UI verification scope is recorded in
[IMPLEMENTATION.md](../../IMPLEMENTATION.md). Runtime receipts, VM identity,
private SSH keys, Chrome assets, disk images, accepted `/data` baseline and
machine configuration live under `.runtime/` and are **not part of the source
release**. A fresh clone must install its prerequisites, prepare its own isolated
environment, validate the Chrome pair, and establish a new accepted baseline and
live acceptance before enabling its worker. Copying old status or hashes into a
new machine's configuration is not an installation procedure.

The guest helpers enforce an Android namespace OUTPUT deny policy, exact
broker-only allowance, immutable container-ID cleanup, state locks, lease-specific
staging, source and installed asset checks, environment/helper hashes, and native
expiry. Chrome's declared static-library version must match the versioned
Trichrome registration, resolved library path and installed APK hash. The live
proof cannot be replaced with source-file existence.

`guest_session.py recover-idle` accepts only
`{"lease_id":"00000000000000000000000000000000"}`. It refuses a live lease,
cleans only its own expired labelled container, and restores binder/data mounts
and deny rules without starting Android. The startup wrapper
`resume_worker.py` also verifies the recorded VM UUID, name and configuration
path. Do not run recovery, bootstrap or another acceptance runner concurrently
with an active lease.

Source APK pins for the accepted SDK build:

- Chrome: `e19853ab32bb80fb99e5aa4fa511e75193c690cf2f37922a3e9eb5894e03b6dc`
- Trichrome: `5266ae77797dc67fd77394e96de2e3e8ad124c58e21cfff91ee46d040680041c`

The API34 image's older Chrome 113 is not the accepted production browser.

## Local environment, 2026-10-28

Verified on this Windows host:

- VirtualBox 7.2.16; new VM `fxfetch-android-worker`, 2 CPUs, 4096 MiB RAM.
- Official Ubuntu 24.04 cloud image dated 20261017, SHA-256 checked before use.
- Guest kernel `6.8.0-147-generic`, Python 3.12.3, Docker 29.1.3; cloud-init completed without errors.
- A dedicated 16 GiB virtual disk, with no shared folders, USB, clipboard,
  drag-and-drop or remote desktop. VM SSH forwards **127.0.0.1:12222** only.
- Binder module loaded and binderfs devices allocated in the new VM.
- Official Redroid Android 14 linux/amd64 image locked to
  `sha256:11d58a64bfbde2253d1cce81bff409ff58174980222d1bada232d9ef59181191`.
- A separate 2 GiB ext4 loop volume mounted on Android `/data`. The VM itself
  supplies a separate upper bound for the rest of the guest disk and memory.
- The first Android boot is offline: guest nftables rules deny all new traffic
  arriving from the dedicated `fxfetch-and` bridge. ADB publishes only on
  **guest 127.0.0.1:15600**. There is no Windows/LAN ADB mapping.

Android boot completion, Chrome operation, session isolation, write-full tests,
controlled broker access, DNS delegation tests and all production guard tests
are separate acceptance steps. The existence of the VM or these scripts does
not establish them. Current runtime receipts are in
`.runtime/android-worker/`; they must not enter Git.

Unrelated VMs, Docker Desktop containers, WSL distributions,
`.wslconfig`, host proxy and host DNS configuration were not changed by these
scripts. The WSL stock kernel is not treated as a dedicated Android VM.

## Explicit deployment steps

Run from the repository root using this project's Python environment:

```powershell
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py status
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py download
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py prepare
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py start
```

`download` uses HTTPS without environment/system proxies, verifies pinned
publisher hashes, retains failed partials and has no automatic retries.
`prepare` refuses existing VM names/directories, never overwrites an old VM,
generates a task-specific SSH key and local NoCloud ISO, and creates only the
named VM. The private key stays in `.runtime`; restrict its ACL to the operator
before use. `start` uses headless VirtualBox. No Windows service is installed.

The original API34 infrastructure download command is retained for provenance:

```powershell
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py download-chrome-image
```

**Do not use this legacy command to prepare the current browser.** It produced
Chrome 113. For a fresh environment, the public API37 r08 tools are:

```powershell
.venv\Scripts\python.exe scripts\android-worker\download_api37.py
.venv\Scripts\python.exe scripts\android-worker\extract_api37.py
```

The first command explicitly downloads the pinned official archive. The second
is offline and extracts only the pinned system/product images, using the sibling
`inspect_google_image.py` parser. Both resolve their output from the repository
location, not the current working directory, and write only under
`.runtime/android-worker/downloads/`. Existing outputs must match their expected
length and digest; retained partials are not silently replaced. Extraction
should have at least 9 GiB of additional free space after the archive exists.
The scripts do not mount images, extract/install APKs, launch Android, or enable
collection. Complete the browser extraction/signature check and installation
with controlled local tools, then establish and verify the worker baseline.
An existing verified archive is reused without a network request.

The official image size and SHA-1 are pinned from Google's SDK repository metadata;
the final receipt additionally records SHA-256. The downloader requests bounded
64 MiB ranges. A failed request exits; after reviewing its failure, `--resume`
continues at the saved byte offset and still verifies the whole final image.
Do not execute arbitrary APKs from the image or use third-party Chrome mirrors.
This helper does not silently accept a different build or turn downloaded bytes
into a successful installation claim.

Copy `guest_environment.py` to the dedicated VM over its SSH connection, then
run `sudo python3 guest_environment.py prepare` and, only for infrastructure
tests, `start-offline`. It verifies the VM marker/hostname, creates only the
dedicated storage/network, installs the deny rules before starting Android,
and schedules an independent systemd stop after 600 seconds. It installs no
target applications and exposes no target navigation command. `stop` stops the
named Android container and preserves the deny rules.

## Runtime boundary

Windows Playwright/CDP connects to **127.0.0.1:19222**, forwarded through SSH
to guest **127.0.0.1:9222**, which is an ADB forwarding socket. That endpoint is
reserved; do not advertise it as live until a verified Chrome session exists.

The only Android data-plane egress will be the project's direct-connect guard
at Windows **127.0.0.1:18767**, reached through VirtualBox NAT as
**10.0.2.2:18767**. This is a local security gateway; it must not forward through
an upstream proxy. The guest must deny all other new Android TCP/UDP/IPv6
connections, including host/private addresses and direct DNS. Docker embedded
DNS needs a specific delegation/leak test; a browser proxy flag alone is not
an egress boundary.

The production controller uses authenticated fixed `begin`, `status`, `end`
and expiry operations, per-task data restoration, a guest-enforced deadline,
fail-closed teardown, and proof tied to the actual running VM/container/Chrome.
Target URLs are structured input to the capture process, never shell fragments.
A timer, a successful `about:blank`, or a readable CDP endpoint does not by
itself authorize collection. Fresh deployments must verify these controls in
their own environment; the source release includes no ready-to-use private
worker configuration or baseline.

For Mac mini, run the API container separately from this privileged Android
worker. Use a dedicated Linux VM or an independently prepared Android worker;
ordinary Docker Desktop on macOS is not assumed to provide Binder, a native
Android kernel, or the same architecture. Android architecture and Chrome
assets must be validated again. Do not pass Docker sockets, ADB, CDP or case
directories into the public-facing API container.

## Stop and recovery

```powershell
.venv\Scripts\python.exe scripts\android-worker\prepare_vm.py stop
```

This sends ACPI shutdown to this VM only. If cleaning up later, first verify the
registered UUID and configuration path against `vm-prepared.json`, confirm the
VM is stopped, and unregister that exact UUID **without** `--delete`. Retain the
project files until their disposition is decided. Never run a wildcard VM
delete, `wsl --shutdown`, Docker Desktop cleanup, or a global nftables flush.

## References and excluded defaults

- [Official Ubuntu cloud image](https://cloud-images.ubuntu.com/noble/20261017/)
- [Google SDK system-image metadata](https://dl.google.com/android/repository/sys-img/google_apis/sys-img2-3.xml)
- [Redroid installation and Binder requirements](https://github.com/remote-android/redroid-doc)
- [NoCloud local seed support](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)
- [Damru source](https://github.com/akwin1234/damru): inspected for environmental requirements;
  not imported or copied into this project. Its default random device/Chrome,
  GPU/TLS modifications, auto-download/setup and network repair routines are
  not the deployment baseline. Its PolyForm Noncommercial licensing also needs
  separate review before reuse.
- [mobilebridge](https://github.com/VulpineOS/mobilebridge): an ADB/CDP bridge,
  not an Android OS, a network guard, or proof of physical-device equivalence.

No Damru, mobilebridge or emulator-farm source is vendored here. These scripts
use ordinary VirtualBox, cloud-init, Linux, Docker, ADB and CDP facilities.
