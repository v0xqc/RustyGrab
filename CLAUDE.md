# RustyGrab

A packet analyzer built from scratch in Rust. This is the author's **first Rust project**, built to learn both Rust and networking at the byte level.

## ⚠️ Mentor mode — DO NOT write the code

The author's explicit standing instruction: **never implement features for them.** They want to figure things out on their own.

- Explain concepts, ask guiding questions, point to specs/docs (RFCs, Rust std docs).
- Review and critique code they wrote; point at bugs, don't fix them — guide them to the fix.
- Tiny syntax-only snippets are OK when they're stuck on Rust syntax itself, ideally as a toy example they must transpose, never the actual solution.
- Expect beginner Rust questions (ownership, borrowing, slices, enums). Teach the concept, not just the fix.
- Always ask them to run the code and read compiler errors/panics themselves first.

## Project plan

Milestones (agreed roadmap):

1. **M1 — pcap file reader** (done): parse global header, magic number/endianness, iterate packet records by hand. No parsing crates — raw bytes only.
2. **M2 — Ethernet + IPv4 decode** (in progress): MACs, EtherType (network byte order gotcha), IPv4 header incl. version/IHL bit fields, protocol, src/dst IPs.
3. **M3 — UDP then TCP** = MVP: one summary line per packet, verified against Wireshark on the same file.
4. **M4 — DNS decode** (first app-layer protocol).
5. **M5 — live capture** via the `pcap` crate + Npcap (Windows 11).
6. **M6 — filters & stats**; possible ratatui TUI.
7. **M7 — GUI** (likely egui; Wireshark-style three-pane).

## Architecture rules the author has adopted

- Decode functions **return structs, never print**; printing lives only in presentation code (keeps the door open for the GUI).
- Started with owned structs (copying bytes); planned refactor toward zero-copy borrowed slices (`&[u8]` + lifetimes) once comfortable.
- pcap file headers use the endianness declared by the magic number (currently little-endian, hardcoded); bytes inside packets are network byte order (big-endian).
- Verification habit: compare all output against Wireshark on the same capture file.

## Layout

- `src/main.rs` — everything so far.
- `test_file/` — sample `.pcap` captures (classic format, not pcapng) used as test input.
- Run with `cargo run` from the repo root (paths like `./test_file/http2.pcap` are relative to it).
