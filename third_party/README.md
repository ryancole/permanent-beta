# Third-party code

## `unicorn-engine-sys` (Unicorn 2.1.5, GPL-2.0)

The published `unicorn-engine-sys` 2.1.5 crate, unpacked as it is on crates.io, with one change. It's used through
`[patch.crates-io]` in the workspace `Cargo.toml`, and only built with `permanent-beta-replay`'s `emulator` feature
(replay of recorded test cases by emulation, design §7.3).

**The change:** `cmake/bundle_static.cmake` makes a hard link (`cmake -E create_hardlink`, after removing an old one)
instead of a symlink (`create_symlink`) from `unicorn.o` to the bundled static library. Windows only lets a
non-administrator create symlinks with Developer Mode on, so the stock crate fails to build on a default Windows
install ("A required privilege is not held by the client"). The Rust build links `unicorn.lib` and never uses
`unicorn.o`. Marked in the file with a `Permanent Beta patch` comment.

**License:** Unicorn is GPL-2.0 (`COPYING`; parts LGPL-2.0, `COPYING.LGPL2`, and glib's, `COPYING_GLIB`). Any binary
built with the `emulator` feature includes it and is GPL-2.0 (design §11.5). Default builds don't include it.

**Building with it** needs, besides MSVC: CMake, Ninja and libclang (bindgen). `corpus/lib/emulator.ps1` finds them
on the PATH, in an LLVM install, or as user-level pip packages:

```bash
python -m pip install --user cmake ninja libclang
```

```bash
cargo test -p permanent-beta-replay --features emulator
```

**Updating:** unpack the new version's `.crate` from `~/.cargo/registry/cache/`, reapply the change, and bump the
`unicorn-engine` requirement in `crates/permanent-beta-replay/Cargo.toml`.
