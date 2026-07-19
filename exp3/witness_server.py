#!/usr/bin/env python3
"""Experiment 3 trusted version witness (run on machine B in the HW test)."""
import argparse, json, os, struct, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

DOMAIN = b"SGXVAULT-EXP3-V1"              # 16 bytes
LOCK = threading.Lock()

def atomic_json(path, obj):
    fd, tmp = tempfile.mkstemp(prefix=path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, sort_keys=True); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def message(vault_id, version, nonce):
    return DOMAIN + bytes.fromhex(vault_id) + struct.pack("<Q", version) + bytes.fromhex(nonce)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(n))
            vid, nonce = req["vault_id"].lower(), req["nonce"].lower()
            if len(bytes.fromhex(vid)) != 16 or len(bytes.fromhex(nonce)) != 32:
                raise ValueError("bad id/nonce length")
            requested = int(req.get("version", 0))
            with LOCK:
                db = json.loads(self.server.db.read_text()) if self.server.db.exists() else {}
                current = int(db.get(vid, 0))
                if self.path == "/commit":
                    if requested < current: self.reply(409, {"error":"rollback", "trusted_version":current}); return
                    current = requested
                    db[vid] = current; atomic_json(self.server.db, db)
                elif self.path != "/query":
                    self.reply(404, {"error":"not found"}); return
            der = self.server.key.sign(message(vid, current, nonce), ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            # SGX SDK uses little-endian r and s.
            sig = r.to_bytes(32,"big")[::-1] + s.to_bytes(32,"big")[::-1]
            self.reply(200, {"vault_id":vid,"trusted_version":current,"nonce":nonce,"signature":sig.hex()})
        except Exception as e: self.reply(400, {"error":str(e)})
    def reply(self, code, obj):
        body=json.dumps(obj,separators=(",",":")).encode(); self.send_response(code)
        self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, fmt, *args): print("[witness]", fmt % args)

def main():
    p=argparse.ArgumentParser(); p.add_argument("--listen",default="127.0.0.1"); p.add_argument("--port",type=int,default=8765)
    p.add_argument("--key",type=Path,default=Path(__file__).with_name("witness_private.pem")); p.add_argument("--db",type=Path,default=Path(__file__).with_name("witness_versions.json")); a=p.parse_args()
    key=serialization.load_pem_private_key(a.key.read_bytes(),None)
    srv=ThreadingHTTPServer((a.listen,a.port),Handler); srv.key=key; srv.db=a.db
    print(f"witness listening on http://{a.listen}:{a.port}, db={a.db}"); srv.serve_forever()
if __name__ == "__main__": main()
