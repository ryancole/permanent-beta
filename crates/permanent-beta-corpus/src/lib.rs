//! Test-corpus tooling (design §10).
//!
//! - [`map`]: parse MSVC linker `/MAP` files.
//! - [`truth`]: join two map files by symbol name into the true old → new function mapping (the answer key).
//!
//! The answer key is only ever used to *score* matching. The analyzer and matchers must never read it.

pub mod map;
pub mod truth;
