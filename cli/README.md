# OpenMLS Proof-Of-Concept CLI Client

This directory contains source code for a proof-of-concept implementation of a
messaging client using OpenMLS. The client requires a running instance of our
proof-of-concept delivery service, which can be found in [delivery-service/ds](https://github.com/openmls/openmls/tree/main/delivery-service/ds) and can be
run from the command line using `cargo run`.

While the code should compile using `cargo build`, the CLI client is neither
very robust nor under active development.

After running the client from the command line (e.g. using `cargo run`). Type
`help` for basic usage.

## Library builds

The crate can also be embedded as a Rust library. [`Client`](src/lib.rs) exposes
the same stateful operations as the interactive program:

```rust
let mut client = cli::Client::new();
client.register("alice")?;
let group = client.create_group()?;
client.send(group, "hello")?;
# Ok::<(), String>(())
```

`cargo build -p cli --lib --release` additionally creates a native dynamic
library (`libcli.so`, `libcli.dylib`, or `cli.dll`, depending on the platform).
Its C ABI is declared in [`include/openmls_cli.h`](include/openmls_cli.h). It
uses an opaque, stateful client handle. Every command returns a JSON string of
the form `{"ok":true,"value":...}` or `{"ok":false,"error":"..."}`; release
those strings with `openmls_cli_string_free`.

The handle is not thread-safe. Calls using the same handle must be serialized,
and a handle must not be used after `openmls_cli_free`.
