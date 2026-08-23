# RustyGrab 🦀

A packet analyzer written from scratch in Rust — no parsing libraries, just raw bytes, offsets, and bit masks. It reads `.pcap` capture files or sniffs live traffic off a network interface, decodes each frame layer by layer, and prints one summary line per packet.

Built as a learning project: every protocol header is parsed by hand against the RFCs.

```
#8 192.168.18.2:59166 -> 172.64.80.1:80 TCP ["PSH", "ACK"] 400
```

## What it decodes

| Layer | Support |
|---|---|
| pcap file format | Global header, per-record headers, magic-number endianness detection (little + big) |
| Ethernet II | Source/destination MAC, EtherType |
| IPv4 | Version, IHL, protocol, source/destination addresses |
| TCP | Source/destination ports, flags (FIN, SYN, RST, PSH, ACK) |
| UDP | Source/destination ports, length |

Anything else — ARP, IPv6, ICMP — is captured and reported as unknown rather than decoded.

## Usage

```
rustygrab read <file.pcap>    Decode packets from a capture file
rustygrab live                List available network interfaces
rustygrab live <index>        Capture and decode live traffic
rustygrab help                Show usage
rustygrab version             Show version
```

Live capture requires **Administrator privileges**. Run `rustygrab live` first to find the index of the interface you want.

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

Sample `.pcap` files live in `test_file/`. More can be found on the [Wireshark sample captures wiki](https://wiki.wireshark.org/SampleCaptures) — note that RustyGrab reads the classic `.pcap` format, not the newer `.pcapng`.

## Roadmap

- [x] pcap file parsing with endianness detection
- [x] Ethernet / IPv4 / TCP / UDP decoding
- [x] CLI with subcommands and input validation
- [x] Live capture via Npcap
- [ ] Restructure into modules (`protocols/`, `source/`)
- [ ] ARP, IPv6, and ICMP decoding
- [ ] Display filters (`--proto`, `--port`)
- [ ] Graceful error handling in decoders (`Result` instead of panics)
- [ ] Graceful Ctrl+C shutdown with capture summary
- [ ] Statistics mode (per-protocol counts, top talkers)
- [ ] Terminal UI, then a Wireshark-style three-pane GUI
