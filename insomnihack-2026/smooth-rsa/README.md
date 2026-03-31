# Smooth RSA

## The Challenge

> Here is our new Smooth™ 0-RTT protocol performing authentication and key exchange in a single request.

This was a crypto challenge where we could connect to a server, and we were given three files:
- The server source code (`server.py`)
- A 2048-bit RSA public key (`public_key.pem`),
- A ciphertext (`c.txt`).

### server.py

```python
#!/usr/bin/python

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from private import flag, expected_aes_key

with open("private_key.pem", "rb") as f:
        data = f.read()

private_key = RSA.import_key(data)
d = private_key.d
n = private_key.n

print("Authenticate yourself by sending the encrypted AES key:")
while True:
    try:
        c = int(input())
    except ValueError:
        print("Error: give me a number.")
        continue
    
    aes_key = pow(c, d, n)
    if aes_key >= 1 << 128:
        print("Error key is too large")
        continue

    if expected_aes_key != aes_key:
        print("Error wrong key")
        continue

    print("\nAuthentication succeeded here is the encrypted flag:")
    cipher = AES.new(long_to_bytes(aes_key), AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(flag)

    print((nonce + ciphertext + tag).hex())
    exit()
```

### public_key.pem

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3YYKS/BRY9GIwDvA9AOI
YxGRWvC3kU3h+xmxt2H/XvSw/5IDgMlHmL5nMcgvaY0Sw+5V6HFwlua3BTPmeSXD
KzatwG2126l/oSOnV40p5RV4rVeQd9sOJntbkb51Fz+kp2UG/Yyp+bl+KkE62xDB
glbuwL20kgY4OGUeVkHgLhqe2Sj/FX2y8Fzl+xy8Layg9pLOh22QJoUzHo3wlRp7
DenXrudPO7ObmALDDNnbhqi394fBg0vkNPrTg5pwgxofCbcpC8/hXmeMU4QOJdDl
CO05eKdo7+vjybCzXJ/PjqEtK8mSvdIS5LpHR+J7dq5Uy9UEwG2Vw6wThHTVWHDM
GwIDAQAB
-----END PUBLIC KEY-----
```

We can inspect it with OpenSSL:

```bash
$ openssl rsa -pubin -in public_key.pem -text -noout
Public-Key: (2048 bit)
Modulus:
    00:dd:86:0a:4b:f0:51:63:d1:88:c0:3b:c0:f4:03:
    ...
Exponent: 65537 (0x10001)
```

So $n$ is a 2048-bit RSA modulus and $e = 65537$.

### c.txt

```
3227373577593336048379530132111996583661354653402137933092594205391382591402...
```

We can check its size:

```python
>>> c = int(open("c.txt").read())
>>> c.bit_length()
2045
```

A 2045-bit integer, the RSA encryption of the secret AES key $m$.

### What the Server Does

The server reads an integer $c$ from the client and RSA-decrypts it to obtain $m = c^d \bmod n$ (the variable `aes_key` in the source). It then branches on the result:

- If $m \geq 2^{128}$: responds `"Error key is too large"`.
- If $m < 2^{128}$ but incorrect: responds `"Error wrong key"`.
- If $m$ is the expected AES key: encrypts the flag with AES-GCM and prints the ciphertext.

The goal is to recover $m$, a 128-bit AES key, using only this oracle, then use it to decrypt the flag.

## The Theory

### RSA's Multiplicative Homomorphism

Textbook RSA has a well-known property: given a ciphertext $c = m^e \bmod n$, we can compute $(f^e \cdot c) \bmod n$ for any factor $f$. When the server decrypts this, it gets:

$$(f^e \cdot c)^d = f \cdot m \pmod{n}$$

This means we can make the server evaluate $f \cdot m \bmod n$ for any $f$ of our choosing, without knowing $m$ or $d$.

### The Threshold Oracle

The server tells us whether the decrypted value is below $B = 2^{128}$. Combined with the homomorphism, sending $f^e \cdot c \bmod n$ lets us ask:

> Is $f \cdot m \bmod n$ less than $B$?

For "small" $f$ values (specifically $f < n/m \approx 2^{1920}$), there is no modular wraparound, so $f \cdot m \bmod n = f \cdot m$ exactly. The oracle then answers the simpler question: is $f \cdot m < B$?

### Similarity to Manger's Attack

This is essentially the same oracle as in [Manger's attack](https://archiv.infsec.ethz.ch/education/fs08/secsem/Manger01.pdf) on RSA-OAEP: a threshold test on the RSA-decrypted value, combined with the multiplicative homomorphism to choose the multiplier. In Manger's setting, $B \approx n/256$, so the gap between $B$ and $n$ is small and the attack converges in a few hundred queries.

Here the gap is enormous: $B = 2^{128}$ while $n \approx 2^{2048}$, so $n/B \approx 2^{1920}$. Manger's step 2, which needs $O(n/B)$ queries to bring the candidate interval into range, is infeasible. We need a different way to exploit the same oracle.

### The Smooth Number Insight

The challenge is called smooth-RSA. In number theory, a $k$-smooth number is one whose prime factors are all at most $k$. The hint: the AES key $m$ may be a smooth number, i.e., composed of small prime factors.

### The Divisibility Oracle

The homomorphism gives us a one-query divisibility test. To check whether a prime $p$ divides $m$:

1. Compute $p^{-1} \bmod n$ (the modular inverse).
2. Send $(p^{-1})^e \cdot c \bmod n$ to the server.
3. The server computes $p^{-1} \cdot m \bmod n$.

If $p \mid m$, then $m/p$ is an integer strictly smaller than $m < 2^{128}$, so $m/p < B$ and the server says "wrong key" (True).

If $p \nmid m$, then $p^{-1} \cdot m \bmod n$ is a pseudorandom element of $[0, n)$. Since $n \approx 2^{2048}$ and $B = 2^{128}$, the probability of this landing below $B$ is $2^{-1920}$, which is negligible. The server says "too large" (False).

This is reliable enough to treat as an oracle.

### All Together Now

The attack proceeds in three phases:

1. __Factor out the smooth part:__ Test each small prime $p$ with the divisibility oracle. Accumulate the product of all primes (with multiplicity) that divide $m$. This leaves a cofactor $L = m / \text{known}$ that has no small prime factors.

2. __Binary search on the cofactor:__ Divide out the known factors to get a ciphertext that decrypts to $L$. Then use the threshold oracle with increasing multipliers $f$ to determine the exact magnitude of $L$, narrowing it to a handful of candidates.

3. __Brute-force:__ Try each remaining candidate by encrypting it and sending it to the server. The correct one triggers the flag.

## The Attack

### Setup: Oracle and Parameters

```python
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
```

The `Oracle` class wraps the TCP connection. Its key method is `query_mul(f)`, which sends $f^e \cdot c \bmod n$ and returns `True` if the server says "wrong key" (decrypted value $< B$), `False` if "too large", or the flag hex string on success:

```python
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
        return self.query(pow(factor, e, n) * c % n)
```

### Phase 1: Extract the Smooth Part

We iterate over all primes up to 1000 and test each one using the divisibility oracle. When a prime $p$ divides $m / \text{known}$, we multiply it into `known` and test again (to find prime powers like $p^2, p^3$, etc.):

```python
def find_smooth_part(oracle, prime_limit=1000):
    known = 1
    primes = primes_up_to(prime_limit)

    for p in primes:
        divisor = known * p
        while oracle.query_mul(pow(divisor, -1, n)):
            known = divisor
            divisor *= p

    return known
```

Each prime costs one query if it doesn't divide $m$, or $k+1$ queries if $p^k$ divides $m$. With 168 primes up to 1000 and 9 factor hits, Phase 1 uses 177 queries and finds:

```
known = 2 × 17 × 23 × 41 × 71 × 307 × 461 × 883 × 971
      = 276228314128798622   (58 bits)
```

The remaining cofactor $L = m / \text{known}$ has no prime factors below 1000.

### Phase 2: Narrow the Cofactor with Binary Search

We now work with $L$ directly. First, we construct a ciphertext that decrypts to $L$ by dividing out the known factors homomorphically:

$$c_L = (\text{known}^{-1})^e \cdot c \bmod n$$

Decrypting: $c_L^{\,d} = \text{known}^{-1} \cdot m = L \pmod{n}$.

Then we search for the transition point of the oracle $f \cdot L < B$. We use geometric doubling to quickly bracket the transition ($f = 1, 2, 4, 8, \ldots$ until the first False), then binary search within the bracket:

```python
def narrow_cofactor(oracle, known):
    c_L = pow(pow(known, -1, n), e, n) * c % n

    def test(f):
        return oracle.query(pow(f, e, n) * c_L % n)

    f_lo, f_hi = 1, 2
    while test(f_hi) is True:
        f_lo, f_hi = f_hi, f_hi * 2

    while f_hi - f_lo > 1:
        f_mid = (f_lo + f_hi) // 2
        if test(f_mid):
            f_lo = f_mid
        else:
            f_hi = f_mid

    L_min = -(-B // f_hi)
    L_max =  (B - 1) // f_lo
    return L_min, L_max
```

The geometric phase finds that $f$ transitions somewhere in $[2^{61}, 2^{62}]$ in 62 queries. The binary search then refines this in another 61 queries, converging to consecutive integers $f_\text{lo}$ and $f_\text{hi} = f_\text{lo} + 1$. At this point we know:

- $f_\text{lo} \cdot L < B$ (last True), so $L \leq \lfloor (B-1) / f_\text{lo} \rfloor$
- $f_\text{hi} \cdot L \geq B$ (first False), so $L \geq \lceil B / f_\text{hi} \rceil$

This pins $L$ to a small interval. Total for Phase 2: 123 queries, yielding:

$$L \in \bigl[\lceil B / f_\text{hi} \rceil,\; \lfloor (B-1) / f_\text{lo} \rfloor\bigr] = [86386479537905784378,\; 86386479537905784399]$$

Only 22 candidates remain.

### Phase 3: Brute-Force

This phase requires no oracle queries at all. For each candidate, we compute $m = \text{known} \times L$ and check locally whether $m^e \bmod n$ equals the known ciphertext $c$. Only the correct $m$ is then sent to the server to retrieve the encrypted flag:

```python
def brute_force(oracle, known, L_min, L_max):
    for i, L in enumerate(range(L_min, L_max + 1)):
        if pow(known * L, e, n) == c:
            m = known * L
            result = oracle.query(pow(m, e, n))
            return m, result
    raise RuntimeError("no valid candidate found")
```

On candidate 12 of 22, the local check matches. A single query to the server retrieves the encrypted flag.

### Decryption

The server returns an AES-GCM blob: nonce (16 bytes) || ciphertext || tag (16 bytes). We decrypt it with $m$ as the 128-bit key:

```python
def decrypt_flag(m, flag_hex):
    raw = bytes.fromhex(flag_hex)
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    aes_key = long_to_bytes(m).rjust(16, b"\x00")
    return AES.new(aes_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
```

### Final Result and Flag

```
m = 23862391606277673436534451941132311958
  = 2 × 17 × 23 × 41 × 71 × 307 × 461 × 883 × 971 × 86386479537905784389
```

In total, **301 queries**: 177 for divisibility testing, 123 for the geometric+binary search, and 1 to authenticate and retrieve the flag.

```
INS{My_A3S_key_is_50_Smooooooth!}
```
