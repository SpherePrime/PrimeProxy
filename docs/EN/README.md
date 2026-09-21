<div align="center">

**[🇷🇺 Русский](../README.md) • 🇬🇧 English**

</div>

<p align="center">
  <a href="https://github.com/Lil-KALINOV/SwiftProxy/releases"><img src="https://img.shields.io/github/v/release/Lil-KALINOV/SwiftProxy?label=release&color=%23ff7b00" alt="Release"></a>
  <a href="https://github.com/Lil-KALINOV/SwiftProxy/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/Lil-KALINOV/SwiftProxy/build.yml?label=build&color=%23ff7b00" alt="Build"></a>
  <a href="https://github.com/Lil-KALINOV/SwiftProxy/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Lil-KALINOV/SwiftProxy?color=%23ff7b00" alt="License"></a>
</p>

<div align="center">
  <img width="180" alt="SwiftProxy" src="../images/swiftproxy-mark.png" />
</div>

# SwiftProxy

**Local MTProto proxy** for Telegram Desktop that **speeds up Telegram**, redirecting traffic through WebSocket connections. Data is transmitted in the same encrypted form, and no external servers are needed.

> [!TIP]
>
> ### [🎉 Support Me](../EN/Funding.md)

> [!CAUTION]
>
> ### Antivirus Detection
>
> Antivirus software sometimes incorrectly marks the application as a virus due to the packer.  
> If you cannot download due to antivirus blocking, then:
>
> 1) **Try downloading the Windows 7 version (functionally identical)**
> 2) Temporarily disable antivirus during download, add the file to exclusions, then re-enable  
>
> Always verify what you download from the internet, especially from untrusted sources. It's best to check detections from well-known antivirus vendors on VirusTotal.

## ✨ Features

- ⚡ **Speed up Telegram** — traffic goes through WebSocket connections to Telegram data centers
- 🔒 **No third-party servers** — everything runs on your device, encryption is preserved
- 🪶 **Tray application** for Windows, macOS, and Linux with a GUI settings editor
- 🔄 **One-click setup** — «Open in Telegram»
- 🛡 **Fake TLS masking** for blocking providers
- ☁️ **Cloudflare bypass** — CF Proxy and Cloudflare Worker support for the most restricted networks
- 📦 **Ready-made builds** — Windows (incl. ARM64 and Windows 7), macOS (universal), Linux (.deb/.rpm)

## 🚀 Quick Start

- **[Windows](./README.windows.md)**
- **[macOS](./README.macos.md)**
- **[Linux](./README.linux.md)**
- **[Docker](./README.docker.md)**

### Windows

Go to the [releases page](https://github.com/Lil-KALINOV/SwiftProxy/releases) and download:

- `SwiftProxy_windows.exe` (Windows 10+ x64)
- `SwiftProxy_windows_arm64.exe` (Windows 10+ ARM64)
- `SwiftProxy_windows_7_64bit.exe` (Windows 7 x64)
- `SwiftProxy_windows_7_32bit.exe` (Windows 7 x32)

On first launch, a window will open with instructions for connecting Telegram Desktop. **The application minimizes to system tray.**

## 📖 Documentation

- [Cloudflare Worker Setup (free alternative to CF proxy)](./CfWorker.md)
- [Cloudflare Domain Setup (CF proxy)](./CfProxy.md)
- [Telegram Test Environment (Test DCs)](./TestDc.md)
- [Fake TLS + upstream in Nginx](./FakeTlsNginx.md)
- [Tray Application Configuration Files](./TrayConfig.md)
- [Building from Source](./BuildFromSource.md)
- [Contributor Guide](./CONTRIBUTING.md)

## 🖥 Tray Menu

- **Open in Telegram** — automatically configure proxy via `tg://proxy` link
- **Copy Link** — copy the proxy connection link
- **Restart Proxy** — restart without exiting the application
- **Settings...** — GUI configuration editor (version, theme, language, optional GitHub update checks)
- **Open Logs** — open log file
- **Exit** — stop proxy and close application

## 🔧 Configuring Telegram Desktop

**Automatic Setup**

Right-click the tray icon and select **"Open in Telegram"**.

If it doesn't work (Telegram doesn't open with proxy), follow these steps:

1. Right-click the tray icon and select **"Copy Link"**
2. Send the link to "Saved Messages" in Telegram and click it
3. Connect

**Manual Setup**

1. Telegram → **Settings** → **Advanced** → **Connection type** → **Proxy**
2. Add proxy:
   - **Type:** MTProto
   - **Server:** `127.0.0.1` (or your custom address)
   - **Port:** `1443` (or your custom port)
   - **Secret:** from settings or logs

## ⚙️ How It Works

```
Telegram Desktop → MTProto Proxy (127.0.0.1:1443) → WebSocket → Telegram DC
```

1. Application starts MTProto proxy on `127.0.0.1:1443`
2. Intercepts connections to Telegram IP addresses
3. Extracts DC ID from MTProto obfuscation init packet
4. Establishes WebSocket connection (TLS) to corresponding DC via Telegram domains
5. If WS unavailable (302 redirect) — automatically switches to CfProxy / direct TCP connection

> [!IMPORTANT] 
> ### Photos/Videos Not Loading?
> **In proxy settings, leave only `4:149.154.167.220` in DC → IP**  
> **If that doesn't work, clear the field completely**  
> This issue occurs on non-Premium accounts  
> If still not working, set up your own domain following: [CfProxy.md](./CfProxy.md)

## 🛠 Automatic Build

The project contains a PyInstaller spec ([`packaging/swiftproxy.spec`](../../packaging/swiftproxy.spec)) and GitHub Actions workflow ([`.github/workflows/build.yml`](../../.github/workflows/build.yml)) for automated builds.

Minimum supported OS versions for current binary builds:

- Windows 10+ x64 for `SwiftProxy_windows.exe`
- Windows 10+ ARM64 for `SwiftProxy_windows_arm64.exe`
- Windows 7 (x64) for `SwiftProxy_windows_7_64bit.exe`
- Windows 7 (x32) for `SwiftProxy_windows_7_32bit.exe`
- Intel macOS 10.15+
- Apple Silicon macOS 11.0+
- Linux x86_64 (AppIndicator required for system tray)

## 📄 License

[Business Source License 1.1](../../LICENSE) — the app is free to use, the code is view-only; any production use of the code requires a commercial license.