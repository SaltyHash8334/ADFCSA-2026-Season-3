# CopperCage — Cryptanalysis

**CTF:** ADF CSA 2026 Season 3
**Category:** Cryptanalysis
**Challenge:** CopperCage
**Flag:** `FLAG{R34DY_T0_3SC4P3_WH3N_TH3_D00R_0P3N5_WH1L3_C0PP3R5M17H_3NT3R_7H3_C4G3_xD}`

---

## Scenario

> Deep within the forgotten forges of an ancient cryptographic guild lies the CopperCage, a construct forged not of metal, but of mathematical miscalculation. Its lattice is fine, its modulus strong—but not strong enough.

Three independent levels, each a different "Coppersmith-flavoured" RSA mistake. Each level encrypts a piece of the flag (a "note"); the three notes assemble into the final flag:

| Level | Attack | Note |
|-------|--------|------|
| 1 | Approximate √p+√q hint → factor N (Coppersmith high-bits) → Legendre-symbol decrypt | `FLAG{R34DY_T0_3SC4P3_WH3N` |
| 2 | Franklin-Reiter with unknown offset (e=3, related messages) | `_TH3_D00R_0P3N5_WH1L3_C0PP3R5M17H_3NT3R` |
| 3 | Coppersmith small roots on `(m\|x)³` with x and (m&x) leaked | `_7H3_C4G3_xD}` |

---

## Level 1 — Whisper Weakness (`output_level1.txt`)

### The setup

```python
prime_bits = 1337
prime1, prime2 = getPrime(prime_bits), getPrime(prime_bits)
modulus = prime1 * prime2

factors = [1, 3, 3, 7]      # base = 63, exponent = 14
D_value = 63 ** 14          # 15515568475732467854453889
hint_value = int(D_value * sqrt(prime1) + D_value * sqrt(prime2))
```

A 2674-bit modulus with a **hint** that leaks `√p + √q` scaled by a known constant `D`. Then each bit `b` of the message is encrypted as:

```python
encrypted_piece = (candidate_x**(1337 + b) * rand_val**2674) % modulus
```

where `candidate_x` is chosen so that `legendre(x, p) = legendre(x, q) = -1` (a quadratic non-residue mod both primes).

### Step 1 — recover √p+√q from the hint

`hint = floor(D·(√p + √q))`, so:

```
s = hint / D  ≈  √p + √q        (error < 1/D ≈ 2⁻⁸⁴)
s² = p + q + 2√(pq) = p + q + 2√N
⇒ p + q ≈ s² − 2√N
```

Computing this needs **~1100 digits of precision** (`mpmath.dps = 1100`): `s²` is ~10⁸⁰⁴ and the result is ~10⁴⁰², so ~400 digits of cancellation occur and 600 dps wasn't enough.

### Step 2 — finish the factorisation with Coppersmith

The `int()` truncation in the hint means `p+q` is only known to within ~10¹⁷⁶ — the quadratic `x² − (p+q)x + N` does **not** split exactly. We know the top ~750 of p's 1337 bits, which is exactly the scenario for Coppersmith's "factorisation with high bits known":

```python
p1_approx = int((s + sqrt(s² − 4√N)) / 2)²      # mpmath, 1100 dps
X = 2**601
p_high = ((p1_approx − 2**595) // (2**600)) * (2**600)
# Coppersmith on f(x) = p_high + x, root x0 = p1 − p_high, beta = 0.5
```

I implemented mimoo's `coppersmith_howgrave_univariate` in pure Python (fpylll for LLL + exact Hensel lifting for the root, since the reconstructed polynomial had a 2800-bit-coefficient issue for float root-finding and a multiple-root structure for beta<1 requiring `sqf_part` first). With `mm=10, tt=10` the lattice recovers the exact `p1`:

```
p1*p2 == N  →  True
```

### Step 3 — Goldwasser-Micali style bit decryption

For a ciphertext `c`:

```
legendre(c, p) = legendre(x^(1337+b), p) · legendre(r^2674, p)
              = (−1)^(1337+b) · 1         (r^2674 = (r²)^1337 is a QR)
              = −1 if b = 0,  +1 if b = 1
```

```python
bits = []
for c in encrypted_bits:
    leg = pow(c % p1, (p1-1)//2, p1)      # legendre symbol
    bits.append(1 if leg == 1 else 0)
```

Reassembling the 479 bits gives:

```
[Chapter 1] - Whisper Weakness >>> FLAG{R34DY_T0_3SC4P3_WH3N
```

---

## Level 2 — The Forged Seal (`output_level2.txt`)

### The setup

```python
e = 3
key = RSA.generate(2048)
M1 = note + md5(note).digest()
M2 = note + md5(b'One more time!' + note).digest()
C1 = pow(M1_int, e, key.n)
C2 = pow(M2_int, e, key.n)
```

Two RSA encryptions of the **same message** with e=3, differing only in the appended 16-byte MD5 digest:

```
M1 = note·2¹²⁸ + md5₁(note)          M2 = note·2¹²⁸ + md5₂(note)
⇒ M2 = M1 + d,   where |d| < 2¹²⁹ (unknown, difference of two digests)
```

`M1³ ≥ n` here (the note is ~150 bytes), so a plain cube root does **not** work — this is the Franklin-Reiter related-message attack with an *unknown* small offset.

### Step 1 — find d via the resultant

`C1 = M1³`, `C2 = (M1+d)³`. The two polynomials `x³ − C1` and `(x+d)³ − C2` share the root `x = M1` mod n exactly when `d` is correct. The resultant w.r.t. `x` is a **degree-9 polynomial in d** that vanishes mod n at the true `d`:

```python
R(d) = Res_x(x³ − C1, (x+d)³ − C2)      # sympy resultant, 9 coefficients
ds   = coppersmith_howgrave_univariate(monic(R), n, beta=1, X=2**130)
# → d = 17224190586111786304335194046515521186
```

### Step 2 — Franklin-Reiter gcd with the recovered d

```python
g(x) = gcd(x³ − C1, (x+d)³ − C2)  mod n   →   linear factor x − M1
```

The gcd's linear factor gives `M1` directly; the note is the top bits:

```
M1 >> 128  →  [Chapter 2] - The Forged Seal >>> _TH3_D00R_0P3N5_WH1L3_C0PP3R5M17H_3NT3R
```

**Validation** (important — the resultant can have several small roots, only one is real):

```python
md5(note) == M1 & 2¹²⁸−1          ✓
md5(b'One more time!'+note) == M2 & 2¹²⁸−1   ✓
```

### Pitfall hit during the solve

The first gcd attempt used `(x+d)³ − C2 = x³ + 3dx² + 3d²x + (d³ − C2)` but I accidentally dropped the `d³` constant term in the polynomial construction, which produced a spurious linear factor. The fix: `f2 = [(d³ − C2) mod n, 3d², 3d, 1]`.

---

## Level 3 — The Oracle's Mask (`output_level3.txt`)

### The setup

```python
p, q = getPrime(1024), getPrime(1024)
N = p*q
e = 3
m = bytes_to_long(note)
x = bytes_to_long(os.urandom(256))
c = pow(m | x, e, N)
# output leaks N, e, c, (m & x), and x itself
```

We are given **x** and **(m & x)** — so we know every bit of `m` except the positions where `x` has a 0 bit. Let `u = m & ~x` (the unknown bits of m where x = 0). Since `u` and `x` have disjoint bits:

```
m | x = x + u        (no overlapping bits)
c = (x + u)³ mod N
```

### Coppersmith small roots

`f(u) = (x+u)³ − c = u³ + 3x·u² + 3x²·u + (x³ − c)  (mod N)` is a **monic cubic**. The flag note is only ~50 bytes, so `u < 2⁴⁰⁷`, while `N^(1/3) ≈ 2⁶⁸³` — well inside Coppersmith's bound. A single `small_roots` call with `X = 2⁵¹²` recovers `u`, and:

```python
m = u | (m & x)   →   [Chapter 3] - The Oracle's Mask >>> _7H3_C4G3_xD}
```

---

## How We Solved It — Reasoning

1. **The name tells you the tool.** "CopperCage" = Coppersmith's attack. Every level is a different canonical Coppersmith problem: factorisation with known high bits (L1), small-root-of-resultant (L2), and small roots of a modular polynomial (L3). Knowing that in advance focused the whole solve.

2. **L1: precision analysis beat brute force.** The naive `p+q = round(s² − 2√N)` failed — the hint's `int()` truncation leaves ~176 digits of uncertainty in `p+q`. But it still pins the top ~750 of 1337 bits of `p`, which is *more* than the ~50% needed for Coppersmith's high-bits factorisation. The subtle bit was needing `dps=1100` (not 600) because `s² ≈ 10⁸⁰⁴` and `p+q ≈ 10⁴⁰²` cancel to leave only ~400 digits — too few at 600 dps.

3. **L1: the ciphertext is Goldwasser-Micali in disguise.** `r^2674 = (r²)^1337` is always a quadratic residue, so the Legendre symbol of the ciphertext mod p reveals the bit directly. No lattice needed for decryption — only for the factorisation.

4. **L2: an unknown offset still fits Franklin-Reiter.** The offset `d = md5₂ − md5₁` is unknown, but it's *small* and it's a root of the degree-9 resultant. Coppersmith finds `d`, then the classic gcd takes over. The trap was forgetting the `d³` term in the polynomial — always expand `(x+d)³` carefully before building the lattice/gcd.

5. **L3: the leak is a Coppersmith problem, not a leak.** Getting `x` and `(m&x)` seems like "we know everything", but the bits of `m` where `x=0` are still hidden. The trick is `m|x = x + u` (disjoint bits) turning the leak into a monic cubic with a small root.

6. **Hensel lifting for root extraction.** The reconstructed LLL polynomial has ~2800-bit coefficients — mpmath's numerical `polyroots` never converged. Switching to exact p-adic **Hensel lifting** (find root mod p, lift to > 2X) made root extraction deterministic. For the beta<1 (factoring) case the root is *multiple*, so the square-free part (`sqf_part`) must be taken first.

7. **Always validate.** The resultant had at least one spurious small root; only the `d` whose gcd recovers an `M1` matching both md5 constraints is the real one.

---

## Key Takeaways

- **Coppersmith's method is the Swiss army knife of RSA attacks**: high-bits factorisation, small roots mod N, small roots of resultants — one LLL lattice construction (`coppersmith_howgrave_univariate`) handles all three if you set `beta`, `mm`, `tt`, `X` correctly.
- **Hint precision analysis matters.** A "leaked" √p+√q hint looks like it should split the quadratic instantly, but truncation error forces a lattice step anyway. Check the *magnitude* of the cancellation before choosing float precision.
- **Goldwasser-Micali / Legendre bit leaks**: if the encryption scheme multiplies by `r^(2k)`, the Jacobi/Legendre symbol of the ciphertext is deterministic — factor the modulus and every bit falls out.
- **Related-message attacks work with unknown offsets** via the resultant + Coppersmith; you don't need to know the exact relation, just a bound on it.
- **Robust root-finding**: for CTF Coppersmith implementations, use Hensel lifting instead of floating-point polynomial roots, and remember `sqf_part` for multiple-root cases.
