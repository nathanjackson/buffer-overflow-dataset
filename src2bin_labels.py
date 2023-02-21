import argparse
import os
import subprocess

from collections import defaultdict

import elftools.elf.elffile as elf

# A couple of functions re-used from here: https://github.com/cwgreene/line2addr
def get_lines(binary, base_address=0x0):
    elf_binary = elf.ELFFile(binary)
    dwarf = elf_binary.get_dwarf_info()
    dwarfinfo = elf_binary.get_dwarf_info()

    line_starts = dict()
    line_ends = dict()

    for cu in dwarfinfo.iter_CUs():
        lp = dwarfinfo.line_program_for_CU(cu)
        prev_state = None
        for lpe in lp.get_entries():
            if lpe.state is None:
                continue
            if prev_state:
                filename = lp['file_entry'][prev_state.file - 1].name.decode("utf-8")
                line = prev_state.line
                addr1 = prev_state.address
                addr2 = lpe.state.address

                key = f"{filename}:{line}"
                if key not in line_starts:
                    line_starts[key] = addr1
                else:
                    cs = line_starts[key]
                    line_starts[key] = min(cs, addr1)

                if key not in line_ends:
                    line_ends[key] = addr2
                else:
                    cs = line_ends[key]
                    line_ends[key] = max(cs, addr2)

            if lpe.state.end_sequence:
                prev_state = None
            else:
                prev_state = lpe.state

    return line_starts, line_ends    


def get_addrs(filename, lineno, lines):
    # Also needs to be fixed here
    addrs = []
    referenced_files = {pair[1]:(pair[0],pair[1]) for pair in lines}
    bf = os.path.basename(filename)
    reffile = referenced_files.get(bf, None)
    if reffile:
        for line, addr in lines[reffile][lineno]:
            addrs.append(addr)
    else:
        print("{} is not references in the executable".format(filename))
    return addrs


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("source_labels")
    args = ap.parse_args()

    with open(args.binary, "rb") as b, open(args.source_labels, "r") as f, open("bin_labels.csv", "w") as o:
        o.write("src_location,label,start_addr,end_addr\n")
        for i, line in enumerate(f):
            line = line.rstrip()
            if line == "location,label":
                continue

            location, label = line.split(",")
            src_file, src_line = location.split(":")
            src_line = int(src_line, 0)
            src_file = os.path.basename(src_file)

            starts, ends = get_lines(b)
            key = f"{src_file}:{src_line}"
            start_addr = starts[key]
            end_addr = ends[key]

            o.write(f"{location},{label},{hex(start_addr)},{hex(end_addr)}\n")

