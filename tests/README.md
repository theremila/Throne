# WARP integration tests

Tests cover WireGuard, MASQUE and AmneziaWG in all three traffic paths, including chains, group hops, auto selectors, cross-core bridges, bypass routing, independent identities, persistence and the settings dialog. Generated configurations are checked by ThroneCore.

Place a matching upstream ThroneCore in the build directory with mode 755 before building the tests. Build dependencies are the same as the GUI.

```sh
cmake -S . -B build-dev -G Ninja -DCMAKE_BUILD_TYPE=Release -DINPUT_VERSION=dev-warp -DTHRONE_CONFIG_TESTS=ON
curl -fLo srslist.h https://raw.githubusercontent.com/throneproj/routeprofiles/rule-set/srslist.h
cp /opt/Throne/ThroneCore build-dev/ThroneCore
chmod 755 build-dev/ThroneCore
cmake --build build-dev --target ThroneConfigTests -j3
ctest --test-dir build-dev --output-on-failure
```

Optional HTTPS checks: `QT_QPA_PLATFORM=offscreen ./build-dev/config-tests/Throne --live-db /absolute/path/to/copied/throne.db`. Use a **copy**: the runner changes its routing and settings. `THRONE_LIVE_PROFILE` selects a profile, `THRONE_LIVE_TRANSPORT` selects the transport and `THRONE_LIVE_ORDER` selects `warp-first`, `proxy-first` or `warp-both`. `THRONE_LIVE_REGISTER=1` registers fresh identities when terms were previously accepted. `THRONE_LIVE_INTERFACE` binds physical endpoint sockets when another VPN is active. HTTPS success and the Cloudflare exit indicator are checked; logs and databases remain private.

TUN checks require a separate Linux network namespace, `THRONE_LIVE_TUN=1`, `THRONE_TEST_NETNS=isolated` and an inherited host namespace FD in `THRONE_TEST_HOST_NETNS_FD`. They do not validate host routing or the installed GUI.

`Throne` remains the GUI with tests enabled. The separate `ThroneConfigTests` target writes its runner and a core copy to `config-tests/`, retaining the name required by the release core's parent check. Release builds leave tests off; the runner is not packaged. Linux x64 CI runs these tests against its freshly built core without personal profiles or live WARP registration.
