#!/usr/bin/env python3
"""Reassemble CTAP2 payloads from fido_parse hex dump and CBOR-decode them.
Generates JSON alongside frames.
"""
import sys, binascii, struct, cbor2, json, pathlib
if len(sys.argv) < 2:
    print("usage: ctap2_decode.py <frames.txt>"); sys.exit(1)
frames_path = pathlib.Path(sys.argv[1])
frames = [binascii.unhexlify(l.strip()) for l in frames_path.read_text().splitlines() if l.strip()]
messages = []
cur = None
remaining = 0
for frame in frames:
    byte4 = frame[4]
    if byte4 & 0x80:
        cmd = byte4 & 0x7F
        length = struct.unpack('>H', frame[5:7])[0]
        payload = frame[7:7+min(57, length)]
        remaining = length - len(payload)
        cur = {'cmd': cmd, 'data': bytearray(payload)}
        if remaining == 0:
            messages.append(cur); cur=None
        continue
    if cur is None:
        continue
    chunk = frame[5:5+min(59, remaining)]
    cur['data'].extend(chunk)
    remaining -= len(chunk)
    if remaining == 0:
        messages.append(cur); cur=None
out=[]
for idx,m in enumerate(messages):
    ctap_cmd=m['data'][0]
    payload=bytes(m['data'][1:])
    try:
        decoded=cbor2.loads(payload)
    except Exception as e:
        decoded=f"CBOR error: {e}"
    out.append({'idx':idx,'hid_cmd':m['cmd'],'ctap_cmd':ctap_cmd,'decoded':decoded})
out_file=frames_path.with_suffix('.json')
out_file.write_text(json.dumps(out, indent=2, default=lambda o: o.hex() if isinstance(o,(bytes,bytearray)) else str(o)))
print('wrote',out_file)