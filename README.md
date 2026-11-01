# Pocketwire Bridge

The desktop half of [Pocketwire](https://pocketwire.app/): a small program for **macOS, Windows and Linux** that lets your AI agents send texts from your own phone, with your approval. Keep the computer on and connected to your phone: an iPhone through Messages on a Mac, or an Android phone through [KDE Connect](https://kdeconnect.kde.org/) on any computer.

This repository is the whole Bridge, under the Apache 2.0 license. Every release is built from a tag by this repository's [release workflow](.github/workflows/release.yml) on GitHub's runners, with checksums and signed build provenance, so you can check that the program you run is the code you can read here.

- One binary of about 4 MB with no runtime to install. It uses about 4 MB of memory while connected.
- It talks to `pocketwire.app` only, over TLS: one WebSocket that receives the texts to send and reports what happened to them (see [Network](#network)).
- It keeps its files in one folder (see [Files](#files)) and never runs a shell: messages reach Messages or KDE Connect as program arguments.

## Install

| | |
|---|---|
| macOS | `brew install --cask hubert-rybak/pocketwire/pocketwire-bridge` installs *Pocketwire Bridge.app* (menu bar icon) and the `pocketwire` command. |
| macOS, Linux from source | `brew install hubert-rybak/pocketwire/pocketwire` builds this repository with Cargo. Use the cask or the formula, not both. |
| Windows | `winget install Pocketwire.Bridge` (once the package is listed in winget), or `pocketwire-setup-windows-amd64.exe` (or `-arm64`) from the [latest release](https://github.com/Hubert-Rybak/pocketwire-bridge/releases/latest). It needs no administrator rights, adds the Bridge to the Start menu and the tray, and can start it when you sign in. |
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
pocketwire run                          keep this computer connected and deliver texts
pocketwire app [--background]           background app with a tray icon and a control page
pocketwire connect                      how to connect an AI app
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

## How texts are sent

Every AI app connects to one address, `https://pocketwire.app/mcp`, as a custom connector (a remote MCP server), and signs in to your Pocketwire account. Nothing about AI apps is set up on this computer; `pocketwire connect` prints the address.

1. The AI app asks Pocketwire to send a text. The Pocketwire server receives and stores the recipient's number and the message text, encrypted at rest with a key the server holds, and applies your limits and approval mode. Messages that need your OK wait under [Approvals](https://pocketwire.app/app/approvals) in the dashboard.
2. The server sends the text to this Bridge over its device connection, as a command. While this computer or the phone is offline, it keeps the text queued, for up to 24 hours.
3. The Bridge hands the text to Messages or KDE Connect and reports back whether it was sent. The dashboard shows the history.

The Bridge only delivers: it keeps no message store and has no approval page of its own. Because the server holds the encryption key, the Pocketwire server can read the numbers and texts it stores. The device's private key and the pairing stay on this computer.

For development, `POCKETWIRE_SERVER` points the Bridge at another server.

## Network

| Connection | What goes over it |
|---|---|
| `wss://pocketwire.app/v1/device/ws` | The device connection. The Bridge proves it holds its key by signing a challenge (ECDSA P-256), then receives the texts to send (number and text) and reports their status. |
| `https://pocketwire.app/v1/device/pair` | Pairing, once: the public key and the computer's name. |
| `127.0.0.1:47300` | Answers `/healthz` only, so that a second copy of the Bridge on this computer (the background app, `pocketwire run` or the service) sees that one already runs. |
| `127.0.0.1:47301` | The background app's control page, for pairing and status. It accepts loopback host names only. |

A proxy from `HTTPS_PROXY` (and `NO_PROXY`) is used when set. The Bridge trusts the operating system's certificate store as well as the Mozilla roots.

## Files

The config folder is `~/.config/pocketwire` on Linux, `~/Library/Application Support/pocketwire` on macOS and `%AppData%\pocketwire` on Windows; `POCKETWIRE_CONFIG` moves the config file and everything next to it. Files are written readable by you only (`0600`).

| File | Contents |
|---|---|
| `config.json` | Server, device id, the device's private key and the driver. |
| `panel.key` | The key of the control page. |
| `bridge.log` | The background app's log, started over after 5 MB. |

Pairing files from earlier versions of the Bridge keep working, so upgrading needs no new code. Settings that 0.3 kept in `config.json` for its private local endpoint are ignored. Version 0.3 also left `messages.json` (its recent private messages, with numbers and texts), `phones.json` and a `certs/` folder in this folder; 0.4 doesn't use them, and you can delete them.

## License

Apache License 2.0, see [LICENSE](LICENSE). Pocketwire is a trademark of its owner; the license doesn't cover the name or the logo.
