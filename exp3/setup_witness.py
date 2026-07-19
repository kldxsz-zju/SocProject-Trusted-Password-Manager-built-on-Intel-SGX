#!/usr/bin/env python3
"""Generate the experiment witness key and the Enclave's pinned public-key header."""
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent
KEY = ROOT / "witness_private.pem"
HEADER = ROOT / "sgx-vault-common" / "Enclave" / "WitnessPublicKey.h"

if KEY.exists():
    key = serialization.load_pem_private_key(KEY.read_bytes(), password=None)
else:
    key = ec.generate_private_key(ec.SECP256R1())
    KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    KEY.chmod(0o600)

pub = key.public_key().public_numbers()
def le32(n): return n.to_bytes(32, "big")[::-1]
def arr(b): return ", ".join(f"0x{x:02x}" for x in b)
HEADER.write_text("""#ifndef EXP3_WITNESS_PUBLIC_KEY_H
#define EXP3_WITNESS_PUBLIC_KEY_H
#include <stdint.h>
static const uint8_t EXP3_WITNESS_PUB_X[32] = {%s};
static const uint8_t EXP3_WITNESS_PUB_Y[32] = {%s};
#endif
""" % (arr(le32(pub.x)), arr(le32(pub.y))), encoding="utf-8")
print(f"private key: {KEY}")
print(f"pinned header: {HEADER}")
print("真实双机实验只把 WitnessPublicKey.h 复制到 SGX 客户端，私钥必须留在见证服务器。")
