# Pocketwire Bridge

The desktop half of [Pocketwire](https://pocketwire.app/): a small program for **macOS, Windows and Linux** that lets your AI agents send texts from your own phone, with your approval. Keep the computer on and connected to your phone: an iPhone through Messages on a Mac, or an Android phone through [KDE Connect](https://kdeconnect.kde.org/) on any computer.

This repository is the whole Bridge, under the Apache 2.0 license. Every release is built from a tag by this repository's [release workflow](.github/workflows/release.yml) on GitHub's runners, with checksums and signed build provenance, so you can check that the program you run is the code you can read here.

- One binary of about 4 MB with no runtime to install. It uses about 4 MB of memory while connected.
- It talks to `pocketwire.app` only, over TLS: one WebSocket for commands and one for the private address (see [Network](#network)).
- It keeps its files in one folder (see [Files](#files)) and never runs a shell: messages reach Messages or KDE Connect as program arguments.

## Install

| | |
|---|---|
| macOS | `brew install --cask hubert-rybak/pocketwire/pocketwire-bridge` installs *Pocketwire Bridge.app* (menu bar icon) and the `pocketwire` command. |
| macOS, Linux from source | `brew install hubert-rybak/pocketwire/pocketwire` builds this repository with Cargo. Use the cask or the formula, not both. |
| Windows | `pocketwire-setup-windows-amd64.exe` (or `-arm64`) from the [latest release](https://github.com/Hubert-Rybak/pocketwire-bridge/releases/latest). It needs no administrator rights, adds the Bridge to the Start menu and the tray, and can start it when you sign in. |
| Linux | `pocketwire-linux-amd64` or `-arm64` from the latest release: a static binary that runs on any distribution. |

Then pair the computer with a code from **Devices** in the [dashboard](https://pocketwire.app/app/devices):

```sh
pocketwire app                 # background app: tray icon and a page on 127.0.0.1:47301 for pairing and status
pocketwire pair K7Q2-M9XD      # or pair from a terminal
pocketwire doctor              # which ways of sending work on this computer
```

The app and the installer aren't signed with an Apple or Microsoft certificate yet. macOS asks once (System Settings, Privacy & Security, *Open Anyway*), and Windows SmartScreen may warn (*More info*, *Run anyway*).

## Check a download

Every release has a `SHA256SUMS` file and a provenance attestation for each file, signed through GitHub's Sigstore integration. The attestation records the repository, the tag, the commit and the workflow run that built the file.

```sh
sha256sum --check --ignore-missing SHA256SUMS                       # shasum -a 256 -c on macOS
gh attestation verify pocketwire-linux-amd64 --repo Hubert-Rybak/pocketwire-bridge
```

To compare with your own build, check out the tag and build it the way the workflow does (below). Rust builds are not yet bit for bit reproducible across machines, so the attestation is the way to tie a published file to its source.

## Build from source

You need [Rust](https://rustup.rs/) 1.89 or newer.

```sh
cargo build --release --locked          # target/release/pocketwire
cargo test --locked
```

| Build | Command |
|---|---|
| Linux, static | `rustup target add x86_64-unknown-linux-musl` and `CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --locked --target x86_64-unknown-linux-musl` (needs `musl-tools`) |
| Without the tray icon | `cargo build --release --locked --no-default-features` |
| Windows tray app (no console window) | `cargo build --release --locked --features gui` gives the program the installer calls `PocketwireBridge.exe` |
| Windows installer | `packaging/windows/build.sh <version> <amd64\|arm64> <dir with pocketwire.exe and PocketwireBridge.exe> dist` (needs `makensis`, on Linux too) |
| macOS app | `packaging/macos/build-app.sh <version> dist` on a Mac: universal *Pocketwire Bridge.app*, ad-hoc signed, zipped |

The `gui` feature only changes what happens when the program starts with no arguments: it opens the background app instead of printing the usage. With any argument it is the same command line tool.

## Commands

```
pocketwire pair <CODE> [--server URL] [--name NAME] [--driver NAME] [--kdeconnect-device ID] [--messages-service sms|imessage]
pocketwire run [--local-port N] [--no-open] [--no-relay]
pocketwire app [--background]           background app with a tray icon and a control page
pocketwire connect                      how to connect AI apps on this computer privately
pocketwire mcp                          private MCP over stdio, for AI apps on this computer
pocketwire approvals                    open the page with messages waiting for your approval
pocketwire doctor
pocketwire test-send <+E164> <text>     send one message through the driver (asks first)
pocketwire service install|uninstall    start at sign-in (Windows: the tray app; macOS and Linux: a service)
pocketwire unpair
pocketwire version
```

## Drivers

| Driver | OS | Needs |
|---|---|---|
| `macos-messages` | macOS (default) | Messages signed in; for real SMS an iPhone with *Settings, Messages, Text Message Forwarding* on for this Mac. The first text asks for Automation permission. `--messages-service imessage` sends iMessages. |
| `kdeconnect` | Windows and Linux (default), macOS | KDE Connect paired with your Android phone, with the SMS permission granted in the KDE Connect app on the phone. `--kdeconnect-device <id>` picks a phone (`kdeconnect-cli -l`). |
| `dry-run` | all | Nothing: it prints messages instead of sending them. |

## Private mode

AI apps on the same computer can talk to the Bridge directly, on `http://127.0.0.1:47300/mcp` with the bearer token from the config (`pocketwire connect` prints the setup). Then the number and the text never reach the Pocketwire server: it gets a keyed tag of the number (HMAC with a key that stays in the config), the length and the segment count, so it can still apply your limits, the new recipient rule and the approval mode. When a message needs your OK, the Bridge opens `http://127.0.0.1:47300/approvals`. Scan the QR code there once to approve from your phone too.

AI apps in the cloud reach the Bridge at its private address, `https://<label>.b.pocketwire.app/mcp`. Pocketwire's relay forwards those connections by the TLS server name without decrypting them: TLS ends on this computer, with a Let's Encrypt certificate whose key is created here and never leaves the `certs` folder. Sign-in still goes through Pocketwire's OAuth, and the Bridge checks each token by its hash. `--no-relay` turns the private address off.

For development, `POCKETWIRE_SERVER` points at another server, `POCKETWIRE_RELAY_CERT` and `POCKETWIRE_RELAY_KEY` use a fixed certificate, and `POCKETWIRE_ACME_DIRECTORY` uses another ACME directory, such as Let's Encrypt staging.

## Network

| Connection | What goes over it |
|---|---|
| `wss://pocketwire.app/v1/device/ws` | The device connection. The Bridge proves it holds its key by signing a challenge (ECDSA P-256), then receives commands and reports their status. |
| `wss://pocketwire.app/v1/device/tunnel` | The blind relay: encrypted bytes of connections to the private address, signed in the same way. |
| `https://pocketwire.app/v1/device/pair` | Pairing, once: the public key and the computer's name. |
| Let's Encrypt (`acme-v02.api.letsencrypt.org`) | Getting and renewing the certificate for the private address. |
| `127.0.0.1:47300` and `127.0.0.1:47301` | The private MCP endpoint with the approval page, and the control page. Both accept loopback host names only. |

A proxy from `HTTPS_PROXY` (and `NO_PROXY`) is used when set. The Bridge trusts the operating system's certificate store as well as the Mozilla roots.

## Files

The config folder is `~/.config/pocketwire` on Linux, `~/Library/Application Support/pocketwire` on macOS and `%AppData%\pocketwire` on Windows; `POCKETWIRE_CONFIG` moves the config file and everything next to it. Files are written readable by you only (`0600`).

| File | Contents |
|---|---|
| `config.json` | Server, device id, the device's private key, the driver, the private endpoint's token and the tag key. |
| `messages.json` | The last 200 private messages, for status and approvals. |
| `phones.json` | Hashes of the tokens of phones paired for approvals; delete it to unpair them all. |
| `certs/` | The private address's certificate and key, and the Let's Encrypt account key. |
| `panel.key` | The key of the control page. |
| `bridge.log` | The background app's log, started over after 5 MB. |

Pairing files from earlier versions of the Bridge keep working, so upgrading needs no new code.

## License

Apache License 2.0, see [LICENSE](LICENSE). Pocketwire is a trademark of its owner; the license doesn't cover the name or the logo.
