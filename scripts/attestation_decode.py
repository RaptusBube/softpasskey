#!/usr/bin/env python3
"""Decode a packed attestation object extracted from frames JSON.
Usage: python attestation_decode.py <frames.json> [idx]
If idx omitted, first message containing key 2 (attestationObject) is used.
"""
import sys, json, base64, cbor2, struct, binascii, pathlib
if len(sys.argv) < 2:
    print("usage: attestation_decode.py frames.json [idx]"); sys.exit(1)
frames=json.load(open(sys.argv[1],'r',encoding='utf-8'))
sel=int(sys.argv[2]) if len(sys.argv)>2 else None
obj=None
for f in frames:
    if f.get('ctap_cmd')==0 and isinstance(f.get('decoded'),dict):
        if '1' in f['decoded'] and '2' in f['decoded'] and '3' in f['decoded']:
            if sel is not None and f['idx']!=sel:
                continue
            obj=f['decoded']
            break
if obj is None:
    sys.exit('attestation object not found')
fmt=obj.get('1')
auth_data_field=obj.get('2')
att_stmt=obj.get('3')
try:
    auth_data=binascii.unhexlify(auth_data_field) if isinstance(auth_data_field,str) else auth_data_field
except Exception:
    auth_data=b''
print('format',fmt)
print('authData len',len(auth_data))
if len(auth_data)>=37:
    flags=auth_data[32]
    print('flags',bin(flags))
    print('rpIdHash',auth_data[:32].hex())
    print('signCount',struct.unpack('>I',auth_data[33:37])[0])
else:
    print('warning: authData shorter than expected')
if isinstance(att_stmt, dict):
    print('alg',att_stmt.get('alg'))
    sig_hex = att_stmt.get('sig','')
    print('sig len',len(sig_hex)//2 if isinstance(sig_hex,str) else 'n/a')
    if 'x5c' in att_stmt:
        print('x5c certs',len(att_stmt['x5c']))
        first_cert = att_stmt['x5c'][0]
        if isinstance(first_cert, str):
            print('first cert (first 40 bytes)', first_cert[:40] + '…')
        else:
            print('first cert type', type(first_cert))
else:
    print('attStmt not a dict:', type(att_stmt))