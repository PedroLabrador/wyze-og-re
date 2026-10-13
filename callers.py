#!/usr/bin/env python3
"""Find callers of a function, resolving PLT stubs correctly.

    python3 callers.py 0x53394                 # by address
    python3 callers.py --name giot_send_create_kcp_session_msg
    python3 callers.py --name X --enclosing   # which fn each call sits in

Why this replaces calls.py
--------------------------
A `bl` in this library targets a PLT STUB, not the real address:

    53f00:  bl  0x13a34                              <- caller writes the stub
    00053394 <giot_send_create_kcp_session_msg>:    <- the real function

So grepping for `bl 0x53394` returns nothing.  Worse, objdump's `<name>`
annotation is applied inconsistently, so grepping for `<iv_gutes_pkt_send_ack>`
returns ONLY the definition line and falsely reads as "no callers".  Both
errors made me declare iv_start_process_calling and giot_on_rcvpkt unreachable;
both were wrong.

The fix: decode each `bl`'s PC-relative target, then consult pltmap.json
(pltmap.py) to translate stub -> real symbol.

Note objdump only annotates PLT calls sometimes, and separates mnemonic from
operand with a LITERAL TAB, so match on the hex column and the raw word.
"""
import json
import re
import sys

# `bl`/`b`/`blx`: addr, word, kind, target, optional <symbol>.
# objdump separates fields with VARIABLE whitespace: the mnemonic is preceded by
# several SPACES after the word and followed by a LITERAL TAB, e.g.
#   '   53598: ebff0119     \tbl\t0x13a04                 @ imm = ...'
# so use \s+ everywhere, never a hard \t right after the hex word.
INS = re.compile(
    r'^\s+([0-9a-f]+):\s+([0-9a-f]{8})\s+(bl|b|blx)\s+0x([0-9a-f]+)'
    r'(?:\s*<([^>]+)>)?')


def sign24(w):
    w &= 0xffffff
    return w - 0x1000000 if w & 0x800000 else w


def load_pltmap():
    try:
        return {int(k, 16): v for k, v in
                json.load(open('/tmp/pltmap.json')).items()}
    except OSError:
        sys.stderr.write('run pltmap.py first to build /tmp/pltmap.json\n')
        return {}


def main():
    argv = sys.argv[1:]
    name = None
    enclosing = '--enclosing' in argv
    argv = [a for a in argv if a != '--enclosing']
    if '--name' in argv:
        i = argv.index('--name')
        name = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]

    pltmap = load_pltmap()
    target = int(argv[0], 16) if argv else None
    if name and target is None:
        for addr, sym in pltmap.items():
            if sym == name:
                target = addr
                break
        if target is None:
            sys.stderr.write('no PLT stub named %s\n' % name)
            return 1

    # collect every instruction, plus enclosing symbol per address
    insns = []
    enclos = {}
    cur = '?'
    addr_list = []
    for line in open('/tmp/p2p_full.txt'):
        m = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if m:
            cur = m.group(2)
            continue
        m = INS.match(line)
        if not m:
            continue
        a = int(m.group(1), 16)
        insns.append((a, int(m.group(2), 16), m.group(3),
                      int(m.group(4), 16), m.group(5)))
        addr_list.append(a)

    def enclosing_of(addr):
        lo, hi = 0, len(addr_list) - 1
        best = -1
        while lo <= hi:
            mid = (lo + hi) // 2
            if addr_list[mid] <= addr:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return None

    # map addr -> enclosing symbol by re-walking (addresses are sorted)
    enc = []
    cur = '?'
    import bisect
    addrs, sym_of = [], []
    for line in open('/tmp/p2p_full.txt'):
        m = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if m:
            sym_of.append(m.group(2))
            addrs.append(int(m.group(1), 16))

    def enclos(addr):
        i = bisect.bisect_right(addrs, addr) - 1
        return sym_of[i] if i >= 0 else '?'

    hits = []
    for a, word, kind, dst, label in insns:
        if kind == 'blx':
            continue
        # a call counts if it targets our address, or targets a stub that
        # resolves to the same symbol name
        matched = (dst == target)
        if not matched and name and pltmap.get(dst) == name:
            matched = True
        if matched:
            hits.append((a, kind, dst, label))

    print('callers of %s 0x%x : %d'
          % (name or 'address', target, len(hits)))
    for a, kind, dst, label in hits:
        who = pltmap.get(dst, '')
        print('  0x%06x %-3s -> 0x%06x %-34s in %s'
              % (a, kind, dst, who or (label or ''), enclos(a)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
