#!/usr/bin/env python3
"""MT19937 Crack — 从 624 个 32-bit 输出恢复 Mersenne Twister 状态.

Usage:
    python3 mt19937_crack.py <file_with_624_numbers>
    echo "123 456 789 ..." | python3 mt19937_crack.py -

Each number should be a 32-bit integer from random.getrandbits(32).
"""
import sys, struct, random

def untemper(y):
    """Reverse the MT19937 tempering transform."""
    # Undo: y ^= y >> 18
    y ^= y >> 18
    # Undo: y ^= (y << 15) & 0xefc60000
    y ^= (y << 15) & 0xefc60000
    # Undo: y ^= (y << 7) & 0x9d2c5680 (need multiple rounds)
    tmp = y
    for _ in range(7):
        tmp = y ^ ((tmp << 7) & 0x9d2c5680)
    y = tmp
    # Undo: y ^= y >> 11 (need two rounds)
    tmp = y
    tmp = y ^ (tmp >> 11)
    y = y ^ (tmp >> 11)
    return y & 0xFFFFFFFF

def clone_mt(outputs):
    """Clone MT19937 state from 624 consecutive 32-bit outputs."""
    assert len(outputs) >= 624, f"Need 624 outputs, got {len(outputs)}"
    state = [untemper(o) for o in outputs[:624]]
    # Reconstruct Python random state
    mt_state = (3, tuple(state + [624]), None)
    rng = random.Random()
    rng.setstate(mt_state)
    return rng

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "-":
        data = sys.stdin.read()
    else:
        with open(sys.argv[1]) as f:
            data = f.read()

    numbers = [int(x) for x in data.split() if x.strip().isdigit()]
    print(f"[*] Read {len(numbers)} numbers")

    if len(numbers) < 624:
        print(f"[!] Need 624 numbers, only got {len(numbers)}")
        sys.exit(1)

    rng = clone_mt(numbers)

    # Verify: predict next values
    print("[*] State recovered. Next 10 predictions:")
    for i in range(10):
        pred = rng.getrandbits(32)
        actual = numbers[624 + i] if 624 + i < len(numbers) else "?"
        match = "✓" if actual != "?" and pred == actual else ("✗" if actual != "?" else "")
        print(f"  [{i}] predicted={pred}, actual={actual} {match}")
