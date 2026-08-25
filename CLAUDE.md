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

The decode path is a tree of nested structs, each layer owning its parsed payload:

```
Packet { count, data_length, ethernet }                     model/packet.rs
  └─ Ethernet { dest_mac, src_mac, ethertype, payload }     protocols/ethernet.rs
       └─ EtherPayload            (dispatch on ethertype)
            ├─ Ipv4  0x0800 → Ipv4Packet  { version, ihl, protocol, src_ip, dest_ip, transport }
            ├─ Ipv6  0x86DD → Ipv6Packet  { version, payload_length, next_header, hop_limit, addrs, transport }
            ├─ Arp   0x0806 → ArpPacket   { opcode, sender_mac/ip, target_mac/ip }
            └─ Other        → raw bytes
                 └─ Transport     (dispatch on IP protocol / next_header)
                      ├─ Icmp    1  → IcmpPacket   { icmp_type, code, body: IcmpBody }
                      ├─ Tcp     6  → TcpSegment   { src_port, dest_port, flags }
                      ├─ Udp     17 → UdpDatagram  { src_port, dest_port, length }
                      ├─ Icmpv6  58 → Icmpv6Packet { icmp_type, code, body: Icmpv6Body }
                      └─ Other      → raw bytes
```

`IcmpBody` is `Echo { identifier, sequence } | Other`. `Icmpv6Body` adds `Neighbor { target: [u8;16] }`. Note the ICMP type numbers differ between v4 and v6 (echo is 8/0 vs 128/129) — that's why they are separate modules; do not share the lookup tables.

Each layer has a `parse(bytes: &[u8]) -> Self` associated function that slices its own header and hands the remainder down. IPv6 currently assumes no extension headers (transport starts at byte 40) — a deliberate simplification. `Endian` is a small enum wrapping `from_le_bytes`/`from_be_bytes` for pcap file-header fields.

Two entry points feed the same `Packet::parse`:
- `source/pcap_file.rs` — walks the pcap file by hand: 24-byte global header, magic-number validation, then 16-byte record headers with the captured length at offset 8. Guards against truncated records.
- `source/live.rs` — `pcap::Capture` loop; `TimeoutExpired` is skipped rather than treated as fatal.

### Rules the author has adopted

- Decode functions **return structs, never print**. Printing lives only in presentation code (`Packet::summary`, the `format_*` helpers) — keeps the door open for the future GUI.
- Currently owned structs (bytes are copied). Planned refactor toward zero-copy borrowed slices (`&[u8]` + lifetimes) once comfortable with lifetimes.
- Endianness: pcap file headers use whatever the magic number declares — both LE and BE are detected in `read_file`. Everything *inside* a packet is network byte order (big-endian), so `from_be_bytes`.
- Verification habit: compare all output against Wireshark on the same capture file.
- Decoders currently `expect()`/panic on malformed input. Converting them to `Result` is a known roadmap item, not an oversight to flag unprompted.

## Layout

```
src/main.rs              mod declarations + main(); delegates to cli
src/cli.rs               arg parsing and command dispatch
src/model/packet.rs      Packet struct + summary() (all output formatting lives here for now)
src/model/other.rs       Other — raw undecoded bytes
src/protocols/           ethernet, arp, ipv4, ipv6, transport, tcp, udp, icmp, icmpv6
src/source/              pcap_file.rs, live.rs
src/ui/, src/stats/, src/filter/, src/error.rs, src/protocols/app/dns.rs
                         empty placeholders for planned work
```

`test_file/` holds public Wireshark sample captures only — **never commit the author's own traffic**. Classic `.pcap` format only, not `.pcapng`. More at the Wireshark sample captures wiki.

## Roadmap

**Done:** pcap file parsing w/ endianness detection and input validation · Ethernet · ARP · IPv4 · IPv6 · TCP · UDP · ICMP · ICMPv6 · CLI subcommands · live capture via Npcap · module restructure.

**Known rough edges** (cosmetic, deliberately deferred — don't flag unprompted):
- `Transport::Other` prints `:0` for ports that don't exist, and says `Other` rather than naming the protocol number.
- `summary()` has two near-identical ICMP `if let` blocks and ~8 parallel `match transport` arms across the IPv4/IPv6 arms. A helper returning `(ports, label, detail)` would collapse them; the author has seen the duplication and is deciding when to act.
- ICMPv6 neighbor discovery doesn't parse the link-layer address options after byte 24, so the MAC being resolved isn't shown.
- Decoders `expect()`/panic on malformed or truncated frames.

**Next, roughly by value:** display filters (`--proto`, `--port`) · `Result` + `?` in decoders (the biggest remaining Rust lesson) · graceful Ctrl+C w/ capture summary · stats mode · ratatui TUI · egui three-pane GUI. DNS (`protocols/app/dns.rs`) was deliberately skipped earlier and remains open.
