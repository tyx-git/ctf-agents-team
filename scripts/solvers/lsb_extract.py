#!/usr/bin/env python3
"""LSB Extract — 从 PNG/BMP 图片中提取 LSB 隐写数据.

Usage:
    python3 lsb_extract.py <image> [--bits N] [--channels RGB] [--order row|col]

Options:
    --bits N        Extract N least significant bits (default: 1)
    --channels C    Channel order: R, G, B, RGB, BGR, etc. (default: RGB)
    --order O       Pixel scan order: row (default) or col

Example:
    python3 lsb_extract.py stego.png
    python3 lsb_extract.py stego.png --bits 2 --channels R
"""
import sys

def extract_lsb(image_path, n_bits=1, channels='RGB', order='row'):
    try:
        from PIL import Image
    except ImportError:
        print("[!] pip install Pillow")
        sys.exit(1)

    im = Image.open(image_path)
    if im.mode not in ('RGB', 'RGBA', 'L'):
        im = im.convert('RGB')

    w, h = im.size
    pixels = im.load()

    channel_map = {'R': 0, 'G': 1, 'B': 2, 'A': 3}
    ch_indices = [channel_map[c] for c in channels.upper() if c in channel_map]

    bits = []

    coords = [(x, y) for y in range(h) for x in range(w)] if order == 'row' \
        else [(x, y) for x in range(w) for y in range(h)]

    for x, y in coords:
        px = pixels[x, y]
        if isinstance(px, int):  # Grayscale
            for bit in range(n_bits):
                bits.append((px >> bit) & 1)
        else:
            for ch in ch_indices:
                if ch < len(px):
                    for bit in range(n_bits):
                        bits.append((px[ch] >> bit) & 1)

    # Convert bits to bytes
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)

    return bytes(result)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    image = sys.argv[1]
    n_bits = 1
    channels = 'RGB'
    order = 'row'

    args = sys.argv[2:]
    for i, arg in enumerate(args):
        if arg == '--bits' and i + 1 < len(args):
            n_bits = int(args[i + 1])
        elif arg == '--channels' and i + 1 < len(args):
            channels = args[i + 1]
        elif arg == '--order' and i + 1 < len(args):
            order = args[i + 1]

    data = extract_lsb(image, n_bits, channels, order)

    # Print summary
    printable = bytes(b for b in data[:500] if 32 <= b < 127 or b in (10, 13))
    print(f"[*] Extracted {len(data)} bytes ({n_bits}-bit LSB, channels={channels}, order={order})")
    print(f"[*] First 200 printable chars:")
    print(printable[:200].decode('ascii', errors='replace'))

    # Check for common patterns
    for pattern in [b'flag{', b'FLAG{', b'CTF{', b'flag', b'PK', b'\x89PNG', b'%PDF']:
        idx = data.find(pattern)
        if idx != -1:
            end = min(idx + 100, len(data))
            print(f"\n[+] Found '{pattern.decode('ascii', errors='replace')}' at offset {idx}:")
            print(f"    {data[idx:end]}")

    # Save raw output
    out_path = image.rsplit('.', 1)[0] + '_lsb.bin'
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"\n[*] Raw data saved to {out_path}")
