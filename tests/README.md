WARP AmneziaWG checks use a temporary database and synthetic identities. They do not register accounts, start a tunnel, or change user settings. QUIC signature generation runs offline in the core.

Place a matching `ThroneCore` in the build directory, then run:

```sh
cmake -S . -B build -DTHRONE_CONFIG_TESTS=ON
cmake --build build --target ThroneConfigTests
ctest --test-dir build --output-on-failure
```

The tests validate generated configurations with the core and check fresh QUIC flights, error propagation, protocol selection, and settings persistence.
