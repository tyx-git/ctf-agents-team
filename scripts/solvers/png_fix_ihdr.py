#!/usr/bin/env python3
"""PNG IHDR Fix — 通过 CRC 爆破修复 PNG 图片的正确宽高.

Usage:
    python3 png_fix_ihdr.py <input.png> [output.png]

Brute-forces the correct width and height by matching the IHDR CRC.
"""
import struct, zlib, sys

def fix_png_dimensions(input_path, output_path=None):
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    # PNG signature check
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        print("[!] Not a valid PNG file")
        return

    # IHDR chunk: offset 8, length at 8:12, type at 12:16, data at 16:29, CRC at 29:33
    ihdr_length = struct.unpack('>I', data[8:12])[0]
    assert ihdr_length == 13, f"Unexpected IHDR length: {ihdr_length}"

    orig_w = struct.unpack('>I', data[16:20])[0]
    orig_h = struct.unpack('>I', data[20:24])[0]
    target_crc = struct.unpack('>I', data[29:33])[0]

    print(f"[*] Current: width={orig_w}, height={orig_h}")
    print(f"[*] Target CRC: {hex(target_crc)}")
    print(f"[*] Brute-forcing correct dimensions...")

    # Brute-force width and height
    ihdr_data = data[12:29]  # 'IHDR' + 13 bytes
    found = False

    for w in range(1, 4096):
        for h in range(1, 4096):
            trial = b'IHDR' + struct.pack('>II', w, h) + bytes(ihdr_data[12:])
            if zlib.crc32(trial) & 0xFFFFFFFF == target_crc:
                print(f"[+] Found: width={w}, height={h}")
                if output_path:
                    data[16:20] = struct.pack('>I', w)
                    data[20:24] = struct.pack('>I', h)
                    with open(output_path, 'wb') as f:
                        f.write(data)
                    print(f"[+] Saved to {output_path}")
                found = True
                break
        if found:
            break

    if not found:
        print("[!] No match found in range 1-4095. Try larger range or check file integrity.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.png', '_fixed.png')
    fix_png_dimensions(input_file, output_file)
