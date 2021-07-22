---
layout: post
title: Binary Ninja Rust Hello World
---

Binary Ninja has [experimental support](https://github.com/Vector35/binaryninja-api/tree/dev/rust)
for writing plugins in Rust and the provided [template](https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples/template)
is a good starting point for figuring out how to write one.

This post will cover some (hopefully useful) getting started tips. A sample
plugin can be found on [GitHub](https://github.com/Ayrx/binja-rs-hello-world).

# rust-toolchain.toml

When this post was written, it was documented that plugins need to be
compiled with Rust Nightly and that the most recent tested version was
`cargo 1.55.0-nightly (9233aa06c 2021-06-22)`. This constraint can be encoded
in a [`rust-toolchain.toml`](https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file)
file in your plugin directory (`targets` need to be changed if an operating
system other than macOS is used):

```toml
[toolchain]
channel = "nightly-2021-06-22"
targets = [ "x86_64-apple-darwin", "aarch64-apple-darwin" ]
```

# Entry Point

A simple Rust plugin would look something like this:

```rust
use binaryninja::binaryview::BinaryView;
use binaryninja::command::register;
use binaryninja::logger;
use log::{info, LevelFilter};

fn hello_world(view: &BinaryView) {
    info!("hello world from Rust!");
}

#[no_mangle]
pub extern "C" fn UIPluginInit() -> bool {
    logger::init(LevelFilter::Info).unwrap();

    register(
        "Hello World!",
        "This is a \"Hello World\" Rust plugin",
        hello_world,
    );
    true
}
```

`UIPluginInit` is the entry point of the plugin and is called when Binary Ninja
launches. Any initialization code, such as registering commands, should be
done within the function.

# Logging

Binary Ninja integrates nicely with the standard Rust
[`log`](https://docs.rs/log/0.4.14/log/)
crate for logging purposes. The logger must be initialized with the following:

```rust
use binaryninja::logger;
use log::{info, LevelFilter};
...
logger::init(LevelFilter::Info).unwrap();
```

The standard `log` macros like `info!` or `error!` can be used to record
information in Binary Ninja's Log pane.

```rust
info!("hello world from Rust!");
```

# Compiling and Using

Cargo is used to build the plugin. In my current setup, I had to explicitly
compile for `x86_64` as Binary Ninja is running under Rosetta 2.

```bash
cargo build --release --target x86_64-apple-darwin
```

Copy the built `.dylib` (or `.so` if on Linux) to the plugins directory:

```bash
cp target/x86_64-apple-darwin/release/libhello_world.dylib \
  ~/Library/Application\ Support/Binary\ Ninja/plugins/
```

The plugin will be registered and ready for use once Binary Ninja is launched.

# API Docs

The Rust API documentation can be built by cloning the
[binaryninja-api](https://github.com/Vector35/binaryninja-api/tree/dev/rust)
repository and running `cargo doc --open` in the `rust/` subdirectory. While
still very sparsely documented, the type information in the API is still very
useful when developing Rust plugins.
