#!/usr/bin/env python3
"""
    python fido_parse.py <dump.txt> [out_frames.txt]
"""
import re, sys
if len(sys.argv) < 2:
    print("usage: fido_parse.py <wireshark_export.txt> [out.txt]", file=sys.stderr)
    sys.exit(1)
path = sys.argv[1]
out_file = sys.argv[2] if len(sys.argv) >= 3 else None
endpoint_re = re.compile(r"Endpoint:\s+0x(04|84)")
hex_re = re.compile(r"(?:Leftover Capture Data|HID Data):\s*([0-9A-Fa-f ]+)")
urb_data_re = re.compile(r"Packet Data Length:\s*(\d+)")
buffer: list[str] = []
cur_ep: int | None = None
with open(path, "r", encoding="utf-8", errors="ignore") as fh:
    for line in fh:
        if m := endpoint_re.search(line):
            cur_ep = int(m.group(1), 16)
            continue
        if m := urb_data_re.search(line):
            if int(m.group(1)) == 0:
                cur_ep = None
            continue
        if m := hex_re.search(line):
            if cur_ep is None:
                continue
            hexbytes = m.group(1).strip().replace(" ", "").lower()
            if hexbytes:
                print(hexbytes)
                if out_file:
                    buffer.append(hexbytes + "\n")
            cur_ep = None
if out_file and buffer:
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.writelines(buffer)
    print(f"saved {len(buffer)} frames to {out_file}")