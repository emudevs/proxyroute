# ProxyRoute

Android 10+ proxy client with a native VPN service, per-app firewall, traffic history and a local connection journal. No account, advertising or analytics.

## Installation

Get the signed universal APK from [GitHub Releases](https://github.com/emudevs/proxyroute/releases). It supports ARM64, ARMv7 and x86-64. Android may ask for permission to install apps from the browser or file manager and may scan the APK with Google Play Protect. ProxyRoute also requests Android's VPN permission on first connection.

The SHA-256 fingerprint of the official signing certificate is `1b68455f6ddc4dcb212dc682525c490faf97f080abe80451abe8d5b1693a9ee0`. Check it with `apksigner verify --print-certs ProxyRoute-1.0.0.apk`.

## Using the app

1. On **Серверы**, add a profile and choose HTTP CONNECT, HTTPS CONNECT or SOCKS5. Enter the proxy server, port and, if required, username and password.
2. Select the profile and tap **Подключить VPN**. Android displays a one-time VPN permission dialog.
3. Set each app's policy in **Брандмауэр**. By default, apps use the selected proxy. Direct and blocked connections appear in **Журнал**. Apps excluded at the Android VPN boundary are outside the journal and chart.
4. To have Android start the chosen profile automatically, open **Настройки постоянного VPN**, select ProxyRoute and enable Always-on VPN. Android's **Block connections without VPN** option also prevents excluded apps from connecting.
5. To use rules and monitoring with standard direct internet access, choose **Только брандмауэр**.

## Network behavior

| Route | Behavior |
|---|---|
| HTTP CONNECT | TCP tunnel with optional Basic authentication. The connection to the proxy is plaintext. |
| HTTPS CONNECT | TCP tunnel over TLS to the proxy, with system CA and host validation and optional Basic authentication. |
| SOCKS5 | TCP CONNECT and UDP ASSOCIATE, with optional username/password authentication. The upstream transport itself is plaintext. |
| Direct via firewall | TCP and UDP egress through protected sockets. Rules and telemetry apply. |
| Exclude from VPN | Android routes the entire app outside ProxyRoute. Shared UIDs fall back to the direct rule and are still logged. Block has precedence for apps sharing a UID. |
| Block | Drops TCP, UDP and DNS flows attributed to the app. If Android cannot supply a flow UID while a block rule is configured, the flow fails closed. |

Android allows one active VPN service per user or profile. A separate Android work profile can use its own VPN. Within one profile, a compatible external app can provide an HTTP or SOCKS5 endpoint that ProxyRoute uses as its upstream.

System-resolved DNS sent to the VPN's virtual DNS appears in the journal and is forwarded as TLS-protected DNS-over-HTTPS to the selected resolver over the applicable route. Explicit app DNS traffic uses the selected rule. HTTP CONNECT has no generic UDP transport. QUIC can fall back to TCP when the app supports it. ICMP is not proxied. The reachability check verifies the configured authentication, CONNECT and a TLS handshake to Cloudflare, so a proxy that deliberately blocks that endpoint may show unavailable.

Credentials are encrypted with Android Keystore. The local journal stores flow metadata and byte totals for seven days, with up to 10,000 recent connections retained after trimming. The chart counts forwarded flow payload bytes in each direction without TUN, IP, TLS or proxy overhead. The forwarder samples counters only while flows transfer data. It takes no wake lock.

## Building

Windows requirements include Go 1.24.4, JDK 17 or 21, Gradle 8.13, Android SDK platform 35, Android Build Tools 35.0.0 and NDK r27. Set JAVA_HOME and, if the SDK and NDK are outside their default locations, ANDROID_HOME and ANDROID_NDK_HOME. Then run:

~~~powershell
powershell -ExecutionPolicy Bypass -File .\build-release.ps1 -RequireExistingKey
~~~

The script produces `dist/ProxyRoute-1.0.0.apk` and verifies its signature and alignment. Official builds require the persistent signing identity in `%LOCALAPPDATA%\ProxyRouteBuild\signing`. Back up the signing key and its password through your private backup process. For a local test build, run `build-native.ps1` and then `gradle :app:assembleDebug`. Keep the public GitHub release signed with the official certificate.

To test the native engine on Linux, run go test -race ./... from native/. The source dependencies and Go Mobile revision are pinned. Bundled dependency licenses are in app/src/main/assets/licenses.

## Features

- The server editor imports HTTP, HTTPS and SOCKS5 URLs, as well as host:port:login:password and host:port@login:password. Use brackets around IPv6 addresses. Addresses without a scheme require an explicit protocol selection.
- The journal can export its retained records as JSON. The file contains timestamps, app names, destinations, routes, error codes and byte counts. The exporter does not read proxy credentials or configuration secrets.
- Firewall settings include separate DNS filters for common advertising and analytics domains and an optional Wi-Fi-only proxy mode. On mobile, Wi-Fi-only mode falls back to the direct tunnel with app rules intact. The bundled filters apply to Android resolver requests handled by ProxyRoute. Domains resolved independently by apps, tunneled connections addressed by IP, and traffic outside the VPN can bypass DNS filtering.
- Choose All apps or Selected only in Firewall → Apps. Set each app’s route in its rule. Explicitly blocked packages are still captured in Selected only mode so their firewall rules apply. Excluded packages are outside the VPN.
- Choose Cloudflare, Google, Quad9, AdGuard, or a custom HTTPS resolver with a bootstrap IP address. Android's own Private DNS is managed separately in system settings.
- The external VPN screen can open another VPN app and add a profile for a local HTTP or SOCKS5 endpoint. Android runs one system VPN per profile. In a single profile, an app offering a local proxy must be able to serve that endpoint without taking over the VPN service.
