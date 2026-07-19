#!/usr/bin/env python3
"""Untrusted transport only: the Enclave, not this helper, verifies the receipt."""
import argparse, json, urllib.request
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("mode",choices=["query","commit"]); p.add_argument("vault_id"); p.add_argument("version",type=int); p.add_argument("nonce"); p.add_argument("output",type=Path); p.add_argument("--url",default="http://127.0.0.1:8765"); a=p.parse_args()
data=json.dumps({"vault_id":a.vault_id,"version":a.version,"nonce":a.nonce}).encode()
req=urllib.request.Request(a.url+"/"+a.mode,data=data,headers={"Content-Type":"application/json"})
with urllib.request.urlopen(req,timeout=5) as r: obj=json.load(r)
# Fixed binary receipt: version LE || nonce || signature(rLE||sLE).
a.output.write_bytes(int(obj["trusted_version"]).to_bytes(8,"little")+bytes.fromhex(obj["nonce"])+bytes.fromhex(obj["signature"]))
