#!/usr/bin/env python3
import socket, sys, time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

HOST, PORT = "smoothrsa.insomnihack.ch", 971
KEY_DIR = sys.argv[1] if len(sys.argv) > 1 else "target"

key = RSA.import_key(open(f"{KEY_DIR}/public_key.pem", "rb").read())
n, e = key.n, key.e
c = int(open(f"{KEY_DIR}/c.txt").read())
B = 1 << 128

class Oracle:
    def __init__(self):
        self.sock = socket.create_connection((HOST, PORT), timeout=15)
        self.buf = b""
        self.queries = 0
        self._recv_line()

    def _recv_line(self):
        while b"\n" not in self.buf:
            self.buf += self.sock.recv(4096)
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode()

    def query(self, ciphertext):
        """Send ciphertext; return True (< B), False (≥ B), or flag hex."""
        self.queries += 1
        self.sock.sendall(f"{ciphertext}\n".encode())
        resp = self._recv_line()
        if not resp.strip():
            resp = self._recv_line()
        if "wrong"     in resp: return True
        if "large"     in resp: return False
        if "succeeded" in resp: return self._recv_line().strip()
        raise RuntimeError(f"unexpected response: {resp!r}")

    def query_mul(self, factor):
        """Query with f^e·c mod n  →  server decrypts to f·m mod n."""
        return self.query(pow(factor, e, n) * c % n)

    def close(self):
        self.sock.close()

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def primes_up_to(limit):
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i*i :: i] = b"\x00" * len(sieve[i*i :: i])
    return [i for i, is_prime in enumerate(sieve) if is_prime]

# Phase 1: extract smooth factors
def find_smooth_part(oracle, prime_limit=1000):
    known = 1
    primes = primes_up_to(prime_limit)
    log(f"Phase 1 — testing {len(primes)} primes up to {prime_limit}")

    for p in primes:
        divisor = known * p
        while oracle.query_mul(pow(divisor, -1, n)):
            known = divisor
            log(f"  ×{p:<4}  known = {known}  ({known.bit_length()} bits, "
                f"q = {oracle.queries})")
            divisor *= p

    log(f"Phase 1 done — known = {known}  ({known.bit_length()} bits, "
        f"q = {oracle.queries})")
    return known

# Phase 2: narrow the cofactor
def narrow_cofactor(oracle, known):
    c_L = pow(pow(known, -1, n), e, n) * c % n

    def test(f):
        return oracle.query(pow(f, e, n) * c_L % n)

    f_lo, f_hi = 1, 2
    while test(f_hi) is True:
        f_lo, f_hi = f_hi, f_hi * 2

    log(f"Phase 2 — binary search on f ∈ [{f_lo}, {f_hi}]  "
        f"({f_hi.bit_length()} bits)")

    while f_hi - f_lo > 1:
        f_mid = (f_lo + f_hi) // 2
        if test(f_mid):
            f_lo = f_mid
        else:
            f_hi = f_mid

    L_min = -(-B // f_hi)
    L_max =  (B - 1) // f_lo
    log(f"Phase 2 done — L ∈ [{L_min}, {L_max}]  "
        f"({L_max - L_min + 1} candidates, q = {oracle.queries})")
    return L_min, L_max

# Phase 3: brute-force remaining candidates
def brute_force(oracle, known, L_min, L_max):
    width = L_max - L_min + 1
    log(f"Phase 3 — brute-forcing {width} candidates")

    for i, L in enumerate(range(L_min, L_max + 1)):
        if pow(known * L, e, n) == c:
            m = known * L
            log(f"  L = {L}  (candidate {i+1}/{width})")
            result = oracle.query(pow(m, e, n))
            return m, result

    raise RuntimeError("no valid candidate found")

def decrypt_flag(m, flag_hex):
    raw = bytes.fromhex(flag_hex)
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    aes_key = long_to_bytes(m).rjust(16, b"\x00")
    return AES.new(aes_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


def main():
    t0 = time.time()
    oracle = Oracle()

    known         = find_smooth_part(oracle)
    L_min, L_max  = narrow_cofactor(oracle, known)
    m, flag_hex   = brute_force(oracle, known, L_min, L_max)
    flag          = decrypt_flag(m, flag_hex).decode()

    log(f"Flag: {flag}")
    log(f"Total: {oracle.queries} queries in {time.time() - t0:.1f}s")
    oracle.close()


if __name__ == "__main__":
    main()
