# RustyGrab

A packet analyzer built from scratch in Rust. This is the author's **first Rust project**, built to learn both Rust and networking at the byte level. Every protocol header is parsed by hand against the RFCs — no parsing crates.

## ⚠️ Mentor mode — DO NOT write the code

The author's explicit standing instruction: **never implement features for them.** They want to figure things out on their own.

- Explain concepts, ask guiding questions, point to specs/docs (RFCs, Rust std docs).
- Review and critique code they wrote; point at bugs, don't fix them — guide them to the fix.
- Tiny syntax-only snippets are OK when they're stuck on Rust syntax itself, ideally as a toy example they must transpose, never the actual solution.
- Expect beginner Rust questions (ownership, borrowing, slices, enums). Teach the concept, not just the fix.
- Always ask them to run the code and read compiler errors/panics themselves first.

## ⚠️ Never commit

**The author does all committing in this repo.** Never run `git commit`, `git push`, `git merge`, `git rebase`, or anything else that writes to history or the remote — not even when a change looks finished. Read-only git (`status`, `log`, `diff`, `show`) is fine.

## Commands

```bash
cargo run -- read ./test_file/chargen-tcp.pcap   # decode a capture file
cargo run -- live                                # list interfaces
cargo run -- live <index>                        # live capture (needs Administrator)
cargo build
```

Run from the repo root — paths like `./test_file/chargen-tcp.pcap` are relative to it. Bare `cargo run` with no subcommand just prints a usage error.

**Build prerequisite (Windows):** the `pcap` crate links against Npcap. Needs both the Npcap installer (in WinPcap API-compatible mode) *and* the separate Npcap SDK zip for `wpcap.lib`. Point the linker at the **x64** lib dir before building, per terminal session:

```bash
export LIB="C:\\npcap-sdk\\Lib\\x64;$LIB"
```

Without it the build fails with `LNK1181: cannot open input file 'wpcap.lib'`. The 32-bit `Lib\` copy gives a machine-type mismatch instead. See README.md for full setup.

## Architecture

Everything is in `src/main.rs` (~440 lines). The decode path is a tree of nested structs, each layer owning its parsed payload:

```
Packet { count, data_length, ethernet }
  └─ Ethernet { dest_mac, src_mac, ethertype, payload }
       └─ EtherPayload::Ipv4 | Other            (dispatch on ethertype, 0x0800 = IPv4)
            └─ Ipv4Packet { version, ihl, protocol, src_ip, dest_ip, transport }
                 └─ Transport::Tcp | Udp | Other  (dispatch on IP protocol, 6 / 17)
```

Each layer has a `parse(bytes: &[u8]) -> Self` associated function that slices its own header and hands the remainder down. `Endian` is a small enum wrapping `from_le_bytes`/`from_be_bytes` for pcap file-header fields.

Two entry points feed the same `Packet::parse`:
- `read_file` — walks the pcap file by hand: 24-byte global header, then 16-byte record headers with the captured length at offset 8.
- `live_capture` — `pcap::Capture` loop; `TimeoutExpired` is skipped rather than treated as fatal.

### Rules the author has adopted

- Decode functions **return structs, never print**. Printing lives only in presentation code (`Packet::summary`, the `format_*` helpers) — keeps the door open for the future GUI.
- Currently owned structs (bytes are copied). Planned refactor toward zero-copy borrowed slices (`&[u8]` + lifetimes) once comfortable with lifetimes.
- Endianness: pcap file headers use whatever the magic number declares — both LE and BE are detected in `read_file`. Everything *inside* a packet is network byte order (big-endian), so `from_be_bytes`.
- Verification habit: compare all output against Wireshark on the same capture file.
- Decoders currently `expect()`/panic on malformed input. Converting them to `Result` is a known roadmap item, not an oversight to flag unprompted.

## Layout

- `src/main.rs` — everything so far. Splitting into `protocols/` and `source/` modules is the next planned refactor.
- `test_file/` — sample captures: `chargen-tcp.pcap`, `chargen-udp.pcap`, `ipv4frags.pcap`. Classic `.pcap` format only, **not** `.pcapng`. More at the Wireshark sample captures wiki.

## Roadmap

Done: pcap file parsing w/ endianness detection · Ethernet / IPv4 / TCP / UDP decode · CLI subcommands · live capture via Npcap.

Next: module restructure · ARP / IPv6 / ICMP · display filters (`--proto`, `--port`) · `Result` in decoders · graceful Ctrl+C w/ summary · stats mode · ratatui TUI · egui three-pane GUI.
