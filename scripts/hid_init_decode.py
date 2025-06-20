#!/usr/bin/env python3
"""Decode FIDO HID INIT handshake given request+response hex strings."""
import sys, binascii, struct
if len(sys.argv) < 3:
    print("usage: hid_init_decode.py <init_req_hex> <init_resp_hex>"); sys.exit(1)
req = binascii.unhexlify(sys.argv[1]); resp = binascii.unhexlify(sys.argv[2])
nonce=req[7:15]; nonce_echo=resp[7:15]; assigned=struct.unpack('>I',resp[15:19])[0]
print('nonce',nonce.hex(),'echo ok',nonce==nonce_echo,'CID',hex(assigned))