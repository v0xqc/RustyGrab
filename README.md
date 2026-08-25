# RustyGrab 🦀

A packet analyzer written from scratch in Rust — no parsing libraries, just raw bytes, offsets, and bit masks. It reads `.pcap` capture files or sniffs live traffic off a network interface, decodes each frame layer by layer, and prints one summary line per packet.

Built as a learning project: every protocol header is parsed by hand against the RFCs.

```
#12 192.168.1.20:59166 -> 93.184.216.34:80 TCP ["PSH", "ACK"] 400
#13 93.184.216.34:80 -> 192.168.1.20:59166 TCP ["ACK"] 1466
#14 192.168.1.20 -> 8.8.8.8 ICMP Echo request (seq 3) 74
#15 8.8.8.8 -> 192.168.1.20 ICMP Echo reply (seq 3) 74
#16 Who has 192.168.1.1? Tell 192.168.1.20
#17 192.168.1.1 is at a0:91:ca:fe:41:31
#18 fe80::1 -> fe80::42 ICMPv6 Neighbor solicitation (target fe80::42) 86
```

## What it decodes

| Layer | Fields |
|---|---|
| pcap file format | Global header, per-record headers, magic-number endianness detection (little + big) |
| Ethernet II | Source/destination MAC, EtherType |
| ARP | Opcode, sender/target MAC and IP — rendered as request/reply sentences |
| IPv4 | Version, IHL, protocol, source/destination addresses |
| IPv6 | Version, payload length, next header, hop limit, source/destination addresses |
| TCP | Source/destination ports, flags (FIN, SYN, RST, PSH, ACK) |
| UDP | Source/destination ports, length |
| ICMP | Type, code, echo identifier and sequence |
| ICMPv6 | Type, code, echo identifier/sequence, neighbor discovery target |

Anything not listed is captured and reported as unknown rather than dropped. IPv6 extension headers are not yet walked — the transport layer is assumed to start at byte 40.

## Usage

```
rustygrab read <file.pcap>    Decode packets from a capture file
rustygrab live                List available network interfaces
rustygrab live <index>        Capture and decode live traffic
rustygrab help                Show usage
rustygrab version             Show version
```

Live capture requires **Administrator privileges**. Run `rustygrab live` first to find the index of the interface you want.

## How it works

Each protocol layer is a struct that parses its own header and hands the remaining bytes to the next layer down. Where a layer can contain one of several things, that choice is an enum:

```
Packet
  └─ Ethernet ─ EtherPayload ─┬─ Ipv4Packet ─ Transport ─┬─ TcpSegment
                              │                          ├─ UdpDatagram
                              ├─ Ipv6Packet ─ Transport ─┼─ IcmpPacket
                              │                          ├─ Icmpv6Packet
                              ├─ ArpPacket               └─ Other (raw bytes)
                              └─ Other (raw bytes)
```

Dispatch happens on the field each protocol provides for exactly that purpose — Ethernet's EtherType, IPv4's protocol byte, IPv6's next header. Because IPv4 and IPv6 share the same protocol numbering, both feed the same transport parser.

Decoding never prints; it returns structs. Formatting lives separately, which keeps file input, live capture, and any future UI reading from the same data.

## Building

RustyGrab links against [Npcap](https://npcap.com) for packet capture, which needs two separate downloads.

**1. Npcap installer** — the runtime driver. During installation, tick **"Install Npcap in WinPcap API-compatible Mode."**

**2. Npcap SDK** — a zip containing `wpcap.lib`, which the linker needs at build time. The installer does *not* include it. Unzip it somewhere permanent, e.g. `C:\npcap-sdk`.

**3. Point the linker at the SDK** before building. This is per-terminal-session:

PowerShell:
```powershell
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
```

Bash:
```bash
export LIB="C:\\npcap-sdk\\Lib\\x64;$LIB"
```

Use the **x64** directory — the 32-bit `Lib\` copy produces a machine-type mismatch error. Without this step the build fails with `LNK1181: cannot open input file 'wpcap.lib'`.

Then:
```bash
cargo build
```

To make the setting permanent, add it to your Windows user environment variables, or create `.cargo/config.toml` with a `rustflags = ["-L", "..."]` entry.

## Test captures

Sample `.pcap` files live in `test_file/`, taken from the [Wireshark sample captures wiki](https://wiki.wireshark.org/SampleCaptures). RustyGrab reads the classic `.pcap` format, not the newer `.pcapng`.

Invalid input is rejected rather than misparsed: files are validated by magic number (not extension), truncated records stop the read with a warning, and missing or unreadable files report the OS error.

## Roadmap

- [x] pcap file parsing with endianness detection and input validation
- [x] Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 decoding
- [x] CLI with subcommands
- [x] Live capture via Npcap
- [x] Modular structure (`protocols/`, `source/`, `model/`)
- [ ] Display filters (`--proto`, `--port`)
- [ ] Graceful error handling in decoders (`Result` instead of panics)
- [ ] Graceful Ctrl+C shutdown with capture summary
- [ ] DNS decoding
- [ ] Statistics mode (per-protocol counts, top talkers)
- [ ] Terminal UI, then a Wireshark-style three-pane GUI
