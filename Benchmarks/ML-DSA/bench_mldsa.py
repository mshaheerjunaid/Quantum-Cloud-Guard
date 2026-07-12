import time, statistics, base64
import oqs

ALG = "ML-DSA-87"
N = 1000
MSG = b"qcg-kms recipient public key authenticity benchmark message"

def bench(label, fn, n=N):
    # warm-up
    for _ in range(5): fn()
    ts = []
    for _ in range(n):
        t = time.perf_counter(); fn(); ts.append((time.perf_counter()-t)*1000)
    ts.sort()
    print(f"  {label:12s} min={ts[0]:.4f} mean={statistics.mean(ts):.4f} "
          f"median={statistics.median(ts):.4f} p99={ts[int(n*0.99)]:.4f} max={ts[-1]:.4f} ms")
    return statistics.mean(ts), statistics.median(ts)

print(f"{ALG} benchmark  iterations={N}  liboqs")
print("="*70)

# sizes
with oqs.Signature(ALG) as s:
    pk = s.generate_keypair(); sk = s.export_secret_key()
    sig = s.sign(MSG)
print(f"  sizes: public_key={len(pk)}B  secret_key={len(sk)}B  signature={len(sig)}B")
print("-"*70)

def keygen():
    with oqs.Signature(ALG) as s:
        s.generate_keypair()

def sign():
    with oqs.Signature(ALG, secret_key=sk) as s:
        s.sign(MSG)

def verify():
    with oqs.Signature(ALG) as s:
        s.verify(MSG, sig, pk)

bench("keygen", keygen)
bench("sign", sign)
bench("verify", verify)
print("="*70)
