#!/usr/bin/env python3
"""ZIP Pseudo Encryption Fix — 清除 ZIP 的伪加密标志.

Usage:
    python3 zip_pseudoenc.py <input.zip> [output.zip]

Clears the encryption flag bits in both Local File Headers and
Central Directory Headers, allowing extraction without a password.
"""
import sys

def fix_zip_pseudo_encryption(input_path, output_path=None):
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    fixed = 0

    # Fix Local File Headers (PK\x03\x04)
    i = 0
    while i < len(data) - 4:
        if data[i:i+4] == b'PK\x03\x04':
            # General purpose bit flag at offset +6 (2 bytes)
            flag_offset = i + 6
            flags = data[flag_offset] | (data[flag_offset + 1] << 8)
            if flags & 0x01:  # Bit 0 = encryption flag
                data[flag_offset] = data[flag_offset] & 0xFE  # Clear bit 0
                fixed += 1
                fname_len = data[i+26] | (data[i+27] << 8)
                fname = data[i+30:i+30+fname_len].decode('utf-8', errors='replace')
                print(f"[+] Fixed Local Header: {fname}")
            i += 30  # Skip past fixed header
        else:
            i += 1

    # Fix Central Directory Headers (PK\x01\x02)
    i = 0
    while i < len(data) - 4:
        if data[i:i+4] == b'PK\x01\x02':
            flag_offset = i + 8
            flags = data[flag_offset] | (data[flag_offset + 1] << 8)
            if flags & 0x01:
                data[flag_offset] = data[flag_offset] & 0xFE
                fixed += 1
            i += 46
        else:
            i += 1

    if fixed == 0:
        print("[*] No encryption flags found — file may not be pseudo-encrypted.")
    else:
        print(f"[*] Cleared {fixed} encryption flag(s)")
        out = output_path or input_path.replace('.zip', '_fixed.zip')
        with open(out, 'wb') as f:
            f.write(data)
        print(f"[+] Saved to {out}")
        print(f"[*] Try: unzip {out}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    fix_zip_pseudo_encryption(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
