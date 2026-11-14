# PathChord Netlink utility patch

This directory contains `netlink-packet-utils` 0.5.2 from crates.io, licensed
under MIT. The upstream source revision is
`51ef4512ad03da863a0cb6dbc97186db24fdd267`; the registry archive SHA-256 is
`0ede8a08c71ad5a95cdd0e4e52facd37190977039a4704eb82a283f713747d34`.
The upstream repository is
[rust-netlink/netlink-packet-utils](https://github.com/rust-netlink/netlink-packet-utils).

`netsock` 0.8.0 depends on Netlink crates that require this utility's 0.5 API.
Its `paste` dependency triggers
[RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436).
The local manifest aliases `pastey` 0.2.3 as `paste`, preserving the public
macro re-export, generated method names, and upstream Rust source. The
upstream license and source files are copied without modification.

`tests/buffer_macros.rs` exercises the exported buffer macros from a downstream
crate, including unsigned and signed field setters, native-endian reads and
writes, mutable slices, and short-buffer rejection. The Rust CI runs this
compatibility check with:

```sh
cargo test --locked -p netlink-packet-utils
```

The normal `cargo deny --all-features --locked check advisories` gate also
covers this dependency. Remove the local patch when `netsock` adopts a
Netlink dependency graph that no longer requires the unmaintained macro crate.
