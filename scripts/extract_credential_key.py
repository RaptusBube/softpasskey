#!/usr/bin/env python3
"""Extract credentialPublicKey from authData and dump as PEM.
Usage: python extract_credential_key.py <frames.json> [idx_att=27] > key.pem
"""
import sys, json, binascii, struct, cbor2
from typing import Any
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization
if len(sys.argv) < 2:
    print("usage: extract_credential_key.py frames.json [idx_att]")
    sys.exit(1)
frames=json.load(open(sys.argv[1],'r',encoding='utf-8'))
idx_att=int(sys.argv[2]) if len(sys.argv)>=3 else 27
att_frame=None
for f in frames:
    if f['idx']==idx_att:
        att_frame=f
        break
if not att_frame:
    sys.exit('att idx not found')
att=att_frame['decoded']
auth_data=binascii.unhexlify(att['2'])
rp_id_hash=auth_data[:32]
flags=auth_data[32]
sign_count=struct.unpack('>I',auth_data[33:37])[0]
AT_FLAG=0x40
if not (flags & AT_FLAG):
    sys.exit('authData missing attestedCredentialData')
ptr=37
aaguid=auth_data[ptr:ptr+16]; ptr+=16
cred_id_len=struct.unpack('>H', auth_data[ptr:ptr+2])[0]; ptr+=2
cred_id=auth_data[ptr:ptr+cred_id_len]; ptr+=cred_id_len
cose_key_bytes=auth_data[ptr:]
cose_key=cbor2.loads(cose_key_bytes)
alg=cose_key.get(3)
outfile_path=None
if alg==-7:
    x=cose_key[-2]
    y=cose_key[-3]
    pub_nums=ec.EllipticCurvePublicNumbers(int.from_bytes(x,'big'), int.from_bytes(y,'big'), ec.SECP256R1())
    pub_key=pub_nums.public_key()
    pem=pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
elif alg==-8:
    x=cose_key[-2]
    pub_key=ed25519.Ed25519PublicKey.from_public_bytes(x)
    pem=pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
else:
    sys.exit(f'Unsupported alg {alg}')
frames_path=sys.argv[1]
if 'data' in frames_path:
    base=Path(frames_path).stem.replace('_frames','')
    outfile_path=Path(frames_path).parent/f"{base}_pub.pem"
    outfile_path.write_bytes(pem)
    print(f'saved PEM to {outfile_path}')
else:
    sys.stdout.buffer.write(pem)