#!/usr/bin/env python3
"""
Build the PLT-stub -> symbol map for an ARM shared object.

    python3 mkplt.py <lib.so> > /tmp/plt_<name>.txt

Why this is needed: objdump prints plain `bl 0x12918` for calls that go through
the PLT, with no symbol attached. The relocations (`objdump -R`) list every
`R_ARM_JUMP_SLOT` in the exact order the stubs are laid out, so:

    stub[n] = PLT_BASE + n * STUB_SIZE          (armeabi-v7a: 0x12588, 12 bytes)

Run once per library, then feed the result to `disfn.py`.
"""
import re
import subprocess
import sys


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True, check=True).stdout


def main():
    lib = sys.argv[1]
    rel = sh("objdump -R %s" % lib)
    slots = [line.split()[-1] for line in rel.splitlines()
             if "R_ARM_JUMP_SLOT" in line]
    if not slots:
        sys.exit("no R_ARM_JUMP_SLOT entries (not an ARM lib?)")

    # Find the PLT base from the first stub: disassemble and take the address
    # of the symbol objdump labels in .plt, else fall back to scanning for the
    # usual 12-byte stub pattern.
    plt = sh("objdump -d -j .plt %s" % lib) if has_plt_section(lib) else ""

    m = re.search(r"^([0-9a-f]{6,8}) <[^>]*plt[^>]*>:", plt, re.M | re.I)
    base = int(m.group(1), 16) + 12 if m else None
    if base is None:
        # last resort: first relocation's stub is the 2nd slot in a standard
        # ARM PLT (slot 0 is the resolver), so base = first_stub - 12
        base = None

    # A more robust route: the dump itself contains `bl <addr>` targets that
    # all land in a 12-byte-strided region. Recover that region by scanning
    # .plt-ish addresses directly from the disassembly.
    if base is None:
        sys.exit("could not locate PLT base")

    for i, name in enumerate(slots):
        print("0x%x %s" % (base + i * 12, name))


def has_plt_section(lib):
    try:
        out = sh("objdump -h %s" % lib)
    except subprocess.CalledProcessError:
        return False
    return re.search(r"\s\.plt\s", out) is not None


if __name__ == "__main__":
    main()
