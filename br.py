#!/usr/bin/env python3
"""Print every control transfer in [lo, hi) with the instructions guarding it.

    python3 br.py 0x340c4 0x34600

objdump's mnemonics lie about data embedded in .text (jump tables decode as
`andeq` noise), so this prints the RAW word next to the mnemonic and always
shows 4 lines of preceding context.  Use it to answer "what does this
dispatcher do with byte X" and "is there an early return hiding here".
"""
import re
import sys

INS = re.compile(r'^\s+([0-9a-f]+):\s+([0-9a-f]{8})\s+(\w+)\s*(.*)')
BRANCHES = {'b', 'beq', 'bne', 'bge', 'blt', 'bgt', 'ble',
            'bhi', 'bls', 'bcc', 'bcs', 'bpl', 'bmi', 'bvs', 'bvc'}


def main(lo, hi, path='/tmp/p2p_full.txt'):
    lo, hi = int(lo, 16), int(hi, 16)
    ins = []
    for line in open(path):
        m = INS.match(line)
        if not m:
            continue
        a = int(m.group(1), 16)
        if lo <= a < hi:
            ins.append((a, m.group(2), m.group(3), m.group(4).split('@')[0].strip()))

    out = []
    for i, (a, word, mn, op) in enumerate(ins):
        if mn in BRANCHES or mn.startswith('cb') or mn == 'blx':
            ctx = []
            for j in range(max(0, i - 4), i):
                ctx.append('%08x  %s %s' % (ins[j][2] and ins[j][0],
                                            ins[j][2], ins[j][3]))
            out.append('  %08x: %s  %-4s %-32s <- %s'
                       % (a, word, mn, op, ' ; '.join(ctx)))
    print('\n'.join(out))
    print('\n%d transfers in 0x%x..0x%x  (%d instructions total)'
          % (len(out), lo, hi, len(ins)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2], *(sys.argv[3:4] or [])))
