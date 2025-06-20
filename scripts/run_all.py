#!/usr/bin/env python3
"""Convenience wrapper that runs the full parsing/decoding pipeline.
Usage:
    python run_all.py <wireshark_txt_export>
It will generate:
    data/<basename>_frames.txt   – 64-byte HID hex lines
    data/<basename>_frames.json  – decoded CBOR messages
"""
import sys, subprocess, pathlib, shutil
ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'scripts'
DATA = ROOT / 'data'
DATA.mkdir(exist_ok=True)
if len(sys.argv) < 2:
    print("usage: run_all.py <dump.txt>")
    sys.exit(1)
dump_path = pathlib.Path(sys.argv[1]).expanduser().resolve()
if not dump_path.exists():
    sys.exit(f"file not found: {dump_path}")
base = dump_path.stem
frames_txt = DATA / f"{base}_frames.txt"
frames_json = DATA / f"{base}_frames.json"
print("[+] extracting HID frames …")
subprocess.check_call([
    sys.executable,
    str(SCRIPTS / 'fido_parse.py'),
    str(dump_path),
    str(frames_txt),
])
print("[+] decoding CTAP2 CBOR …")
subprocess.check_call([
    sys.executable,
    str(SCRIPTS / 'ctap2_decode.py'),
    str(frames_txt),
])
print("[+] done →", frames_json)