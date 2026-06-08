# NetSentinel — Inter-Process Communication Protocol

## Overview

The C packet engine and the Python detection engine communicate over a
**UNIX domain socket** (`/tmp/netsentinel.sock`).

---

## Transport

| Property        | Value                          |
|-----------------|-------------------------------|
| Socket type     | `AF_UNIX`, `SOCK_STREAM`       |
| Socket path     | `/tmp/netsentinel.sock`        |
| Direction       | C engine → Python engine only  |
| Framing         | Fixed-size binary structs      |
| Byte order      | Native host (little-endian x86)|

---

## Packet Format — `packet_meta_t`

Each message is exactly **48 bytes**, matching the C struct layout in
`packet_engine/include/emitter.h`.

```
Offset  Size  Type      Field
------  ----  --------  ---------------
0       16    char[]    src_ip   (null-padded ASCII dotted-decimal)
16      16    char[]    dst_ip   (null-padded ASCII dotted-decimal)
32       2    uint16_t  src_port (host byte order)
34       2    uint16_t  dst_port (host byte order)
36       1    uint8_t   protocol (IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1)
37       1    uint8_t   tcp_flags
38       2    uint16_t  payload_len
40       4    uint32_t  timestamp_sec   (Unix epoch)
44       4    uint32_t  timestamp_usec
```

Total: **48 bytes per packet event**.

---

## TCP Flag Bitmask

```
Bit 0 (0x01)  FIN
Bit 1 (0x02)  SYN
Bit 2 (0x04)  RST
Bit 3 (0x08)  PSH
Bit 4 (0x10)  ACK
Bit 5 (0x20)  URG
```

---

## Python Struct Format String

```python
PACKET_FMT  = "16s16sHHBBHII"
PACKET_SIZE = struct.calcsize(PACKET_FMT)  # == 48
```

---

## Connection Lifecycle

```
Python server           C client
─────────────────────   ─────────────────────
bind(/tmp/ns.sock)
listen()
                        connect() [with retry]
accept() → conn
                        send(packet_meta_t) ×N
recv() loop …
                        close() on shutdown
```

- The Python server starts first; the C engine retries `connect()` up to 10 times with 1-second delays.
- The connection is long-lived for the duration of capture.
- Multiple C client connections are accepted simultaneously (one per interface if extended).

---

## Error Handling

- Malformed or short reads are silently dropped.
- Non-IP frames are filtered by the C engine before emission (BPF filter: `ip`).
- If the Python server is unreachable after all retries, the C engine exits with a non-zero code and the supervisor restarts it.