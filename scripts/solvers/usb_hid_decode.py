#!/usr/bin/env python3
"""USB HID Keyboard Decode — 从 PCAP 中解码 USB 键盘击键.

Usage:
    python3 usb_hid_decode.py <pcap_file>
    python3 usb_hid_decode.py --raw <hex_data_file>  (每行一个 HID report)

Requires: tshark (for pcap mode)
"""
import sys, subprocess

# USB HID Keyboard scancode → character mapping
KEYMAP = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'), 0x07: ('d', 'D'),
    0x08: ('e', 'E'), 0x09: ('f', 'F'), 0x0A: ('g', 'G'), 0x0B: ('h', 'H'),
    0x0C: ('i', 'I'), 0x0D: ('j', 'J'), 0x0E: ('k', 'K'), 0x0F: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'), 0x13: ('p', 'P'),
    0x14: ('q', 'Q'), 0x15: ('r', 'R'), 0x16: ('s', 'S'), 0x17: ('t', 'T'),
    0x18: ('u', 'U'), 0x19: ('v', 'V'), 0x1A: ('w', 'W'), 0x1B: ('x', 'X'),
    0x1C: ('y', 'Y'), 0x1D: ('z', 'Z'),
    0x1E: ('1', '!'), 0x1F: ('2', '@'), 0x20: ('3', '#'), 0x21: ('4', '$'),
    0x22: ('5', '%'), 0x23: ('6', '^'), 0x24: ('7', '&'), 0x25: ('8', '*'),
    0x26: ('9', '('), 0x27: ('0', ')'),
    0x28: ('\n', '\n'),  # Enter
    0x29: ('[ESC]', '[ESC]'),
    0x2A: ('[BACKSPACE]', '[BACKSPACE]'),
    0x2B: ('\t', '\t'),
    0x2C: (' ', ' '),
    0x2D: ('-', '_'), 0x2E: ('=', '+'), 0x2F: ('[', '{'), 0x30: (']', '}'),
    0x31: ('\\', '|'), 0x33: (';', ':'), 0x34: ("'", '"'),
    0x35: ('`', '~'), 0x36: (',', '<'), 0x37: ('.', '>'), 0x38: ('/', '?'),
}

def decode_hid_reports(reports):
    """Decode HID keyboard reports to text."""
    result = []
    for report in reports:
        if not report or len(report) < 6:
            continue
        # HID report: [modifier, reserved, key1, key2, key3, key4, key5, key6]
        try:
            data = bytes.fromhex(report.replace(":", "").strip())
        except ValueError:
            continue
        if len(data) < 3:
            continue

        modifier = data[0]
        shift = bool(modifier & 0x22)  # Left or Right Shift
        key = data[2]

        if key == 0:
            continue
        if key in KEYMAP:
            char = KEYMAP[key][1 if shift else 0]
            if char == '[BACKSPACE]' and result:
                result.pop()
            else:
                result.append(char)
        else:
            result.append(f'[0x{key:02x}]')

    return ''.join(result)

def extract_from_pcap(pcap_file):
    """Extract USB HID data from pcap using tshark."""
    # Try different field names (varies by tshark version)
    for field in ['usb.capdata', 'usbhid.data']:
        try:
            out = subprocess.check_output(
                ['tshark', '-r', pcap_file, '-T', 'fields', '-e', field,
                 '-Y', f'{field} && usb.transfer_type==0x01'],
                stderr=subprocess.DEVNULL, text=True
            )
            reports = [line.strip() for line in out.strip().split('\n') if line.strip()]
            if reports:
                return reports
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "--raw":
        with open(sys.argv[2]) as f:
            reports = [line.strip() for line in f if line.strip()]
    else:
        reports = extract_from_pcap(sys.argv[1])
        if not reports:
            print("[!] No USB HID data found. Try: tshark -r file.pcap -T fields -e usb.capdata")
            sys.exit(1)

    text = decode_hid_reports(reports)
    print(f"[*] Decoded {len(reports)} reports:")
    print(text)
