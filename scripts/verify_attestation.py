#!/usr/bin/env python3
"""Verify the signature inside a packed attestation.
Usage:
    python verify_attestation.py <frames.json> [idx_att=27] [idx_req=14]
Needs cryptography (pip install cryptography cbor2).
"""
import sys, json, binascii, hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
if len(sys.argv) < 2:
    print("usage: verify_attestation.py frames.json [idx_att] [idx_req]")
    sys.exit(1)
frames=json.load(open(sys.argv[1],'r',encoding='utf-8'))
idx_att=int(sys.argv[2]) if len(sys.argv)>=3 else 27
idx_req=int(sys.argv[3]) if len(sys.argv)>=4 else 14
def get_frame(idx):
    for f in frames:
        if f['idx']==idx:
            return f
    return None
att_frame=get_frame(idx_att)
req_frame=get_frame(idx_req)
if not att_frame or not req_frame:
    sys.exit('idx not found')
att=att_frame['decoded']
client_hash=binascii.unhexlify(req_frame['decoded']['1'])
auth_data=binascii.unhexlify(att['2'])
att_stmt=att['3']
sig=binascii.unhexlify(att_stmt['sig'])
cert_der=binascii.unhexlify(att_stmt['x5c'][0])
cert=load_der_x509_certificate(cert_der)
pub=cert.public_key()
message=auth_data+client_hash
try:
    pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))
    print('signature valid')
except InvalidSignature:
    print('signature INVALID')