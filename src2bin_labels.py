import argparse
import os
import subprocess

from collections import defaultdict

import elftools.elf.elffile as elf

# A couple of functions re-used from here: https://github.com/cwgreene/line2addr
def get_lines(binary, base_address=0x0):
    elf_binary = elf.ELFFile(binary)
    dwarf = elf_binary.get_dwarf_info()
    lines = defaultdict(lambda: defaultdict(lambda:[]))
    for cu in dwarf.iter_CUs():
        lp = dwarf.line_program_for_CU(cu)
        files = lp['file_entry']
        directories = ["."] + [str(d, 'utf8') for d in lp['include_directory']]
        for lpe in lp.get_entries():
            if lpe.state:
                lfile = files[lpe.state.file-1]
                (lines[(directories[lfile['dir_index']], str(lfile['name'], 'utf8'))]
                    [lpe.state.line].append((lpe.command, lpe.state.address+base_address)))
    return lines

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

            lines = get_lines(b)
            addrs = get_addrs(src_file, src_line, lines)
            start_addr = min(addrs)
            end_addr = max(addrs)
            
            o.write(f"{location},{label},{hex(start_addr)},{hex(end_addr)}\n")

