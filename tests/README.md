# WARP chain integration tests

The test runner builds real sing-box/Xray configurations against an isolated temporary SQLite database, follows dialers across both cores, and validates them with ThroneCore. It covers WireGuard/MASQUE/AmneziaWG and both chain orders, single proxies, multi-hop chains, group front/landing proxies, native and Xray auto selectors, WARP bypass, disabled WARP, invalid settings, persistence and the routing dialog.

Use the ThroneCore shipped with the same upstream version as the checkout. The core must be copied beside the test executable; its parent check requires both executable names and directories to match.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DINPUT_VERSION=1.3.2-warp.2 -DTHRONE_CONFIG_TESTS=ON
curl -fLo build/srslist.h https://raw.githubusercontent.com/throneproj/routeprofiles/rule-set/srslist.h
cp /opt/Throne/ThroneCore build/ThroneCore
chmod 755 build/ThroneCore
cmake --build build -j3
ctest --test-dir build --output-on-failure
```

Optional live HTTPS checks use a **copy** of an existing Throne database. The runner modifies that copy's routing profile, disables TUN and the system proxy, uses temporary loopback ports, and checks Cloudflare's `warp` exit indicator. It does not print credentials, endpoints or public IPs. An unsupported or unavailable path fails the check. `THRONE_LIVE_PROFILE` selects a profile ID; `THRONE_LIVE_TRANSPORT` selects `wireguard`, `masque` or `amnezia`.

```sh
QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME= QT_STYLE_OVERRIDE=Fusion \
  ./build/Throne --live-db /absolute/path/to/copied/throne.db
```

Build the GUI for installation by reconfiguring with `-DTHRONE_CONFIG_TESTS=OFF` and rebuilding. The test executable must never be installed as the GUI.

For direct-path diagnostics with another VPN active, set `THRONE_LIVE_INTERFACE` to the physical interface (for example `wlan0`) and `THRONE_LIVE_ORDER=warp-first`. This binds physical WARP endpoint sockets explicitly; unbound tests may otherwise use an already-active VPN. `THRONE_LIVE_MASQUE_HTTP=2` selects HTTP/2 for a MASQUE diagnostic. These variables affect the isolated test configuration only.

`THRONE_LIVE_TUN=1 THRONE_TEST_NETNS=isolated` enables a real TUN test only inside a separate Linux network namespace; the runner checks its namespace against an inherited open FD of the host network namespace (`THRONE_TEST_HOST_NETNS_FD`). Configure networking inside that namespace before launching it. This does not validate the installed GUI's host TUN setup.

For bounded WireGuard diagnostics, `THRONE_LIVE_WG_JUNK=1` adds only preliminary junk packets (`jc=4`, `jmin=40`, `jmax=70`) to the test endpoint, leaving standard WireGuard handshake headers unchanged. `THRONE_LIVE_ENDPOINT_SOCKS_PORT` routes physical test endpoints through an existing loopback SOCKS proxy as a positive control. That control explicitly adds another VPN to the tested path. Neither option changes saved application settings or the release GUI. `THRONE_LIVE_LOG` stores private core logs and startup errors; do not publish these logs without redacting identities and endpoints. Live checks disable ad-block list downloads in the copied settings so an unavailable download cannot be mistaken for a handshake failure.

The `amnezia` WARP mode uses normal Cloudflare WireGuard registration and public QUIC CPS captures from [warp-awg-gen](https://github.com/Skiro1/warp-awg-gen/blob/382001b704a1a6f87429f4601c237937ad420a0e/internal/awg/cps.go), with its MIT notice retained in `WarpCpsPresets.h`. It retains standard WARP packet headers and sizes and adds `Jc=4`, `Jmin=40`, `Jmax=70`, and `I1`. It does not require an imported profile. The routing dialog's Generate button registers fresh keys and chooses editable UDP port 3854 for this mode.

For an opt-in fresh-identity live check on a copied DB, set `THRONE_LIVE_TRANSPORT=amnezia THRONE_LIVE_REGISTER=1`. The copy must already record accepted Cloudflare terms. `THRONE_LIVE_REGISTER_PROXY` can specify the HTTP proxy used for registration only. `THRONE_LIVE_WARP_ENDPOINT` overrides the endpoint in test memory. Bind endpoint sockets with `THRONE_LIVE_INTERFACE` to establish a direct physical path. `THRONE_LIVE_WG_ONLY=1` removes VPS routing for a standalone WARP HTTPS check; `THRONE_LIVE_WG_MTU` overrides endpoint MTU for diagnosis. Logs and the copied DB contain private data and must remain local.
