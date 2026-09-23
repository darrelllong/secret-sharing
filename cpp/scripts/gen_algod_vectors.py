#!/usr/bin/env python3
"""Generate division fixtures and check them against Python integers.

Branch labels describe this Algorithm D model, not measured C++ coverage.
Run: python3 cpp/scripts/gen_algod_vectors.py
"""

BASE = 1 << 64
MASK = BASE - 1


def norm(v):
    while v and v[-1] == 0:
        v.pop()
    return v


def shl_limbs(limbs, shift, size):
    out = [0] * size
    for i, x in enumerate(limbs):
        if shift == 0:
            out[i] = x
        else:
            out[i] |= (x << shift) & MASK
            if i + 1 < size:
                out[i + 1] = x >> (64 - shift)
    return out


def shr_limbs(limbs, shift):
    out = [0] * len(limbs)
    for i in range(len(limbs) - 1, -1, -1):
        if shift == 0:
            out[i] = limbs[i]
        else:
            out[i] |= limbs[i] >> shift
            if i > 0:
                out[i] |= (limbs[i - 1] << (64 - shift)) & MASK
    return out


def to_int(limbs):
    v = 0
    for i in reversed(range(len(limbs))):
        v = (v << 64) | limbs[i]
    return v


def from_int(v, n):
    return [(v >> (64 * i)) & MASK for i in range(n)]


def countl_zero(x):
    return 64 - x.bit_length()


def div_rem_knuth(dividend, divisor):
    """Mirror of big_uint::div_rem_knuth. Returns (q, r, branches)."""
    n = len(divisor)
    m = len(dividend) - n
    branches = set()

    shift = countl_zero(divisor[n - 1])
    div = shl_limbs(divisor, shift, n)
    rem = shl_limbs(dividend, shift, len(dividend) + 1)
    divisor_hi = div[n - 1]
    divisor_next = div[n - 2]

    quotient = [0] * (m + 1)

    for j in range(m + 1, 0, -1):
        j -= 1
        numerator = (rem[j + n] << 64) | rem[j + n - 1]
        q_hat = numerator // divisor_hi
        r_hat = numerator % divisor_hi
        if q_hat >= BASE:
            branches.add("clamp")
        while q_hat >= BASE or q_hat * divisor_next > ((r_hat << 64) | rem[j + n - 2]):
            q_hat -= 1
            r_hat += divisor_hi
            if r_hat >= BASE:
                branches.add("rbreak")
                break

        borrow = 0
        carry = 0
        for i in range(n):
            product = q_hat * div[i] + carry
            carry = product >> 64
            diff = BASE + rem[i + j] - (product & MASK) - borrow
            rem[i + j] = diff & MASK
            borrow = 1 - (diff >> 64)
        diff = BASE + rem[j + n] - carry - borrow
        rem[j + n] = diff & MASK

        if (diff >> 64) == 0:
            branches.add("addback")
            q_hat -= 1
            carry = 0
            for i in range(n):
                s = rem[i + j] + div[i] + carry
                rem[i + j] = s & MASK
                carry = s >> 64
            rem[j + n] = (rem[j + n] + carry) & MASK

        quotient[j] = q_hat

    q = norm(quotient)
    r_limbs = shr_limbs(rem[:n], shift)
    return to_int(q), to_int(norm(r_limbs)), branches


def check(dividend, divisor):
    """Verify against the independent Python-int oracle."""
    u = to_int(dividend)
    v = to_int(divisor)
    q, r = divmod(u, v)
    qk, rk, branches = div_rem_knuth(dividend, divisor)
    assert qk == q, (u, v, q, qk)
    assert rk == r, (u, v, r, rk)
    assert q * v + r == u
    assert 0 <= r < v
    return branches


def hexs(limbs):
    v = to_int(limbs)
    if v == 0:
        return "00"
    return f"{v:0{(v.bit_length() + 7) // 8 * 2}x}"


def int_hex(v):
    if v == 0:
        return "00"
    return f"{v:0{(v.bit_length() + 7) // 8 * 2}x}"


# Extreme limb values for the structured searches.
TOP = [0x8000000000000000, 0x8000000000000001, 0x8000000000000002,
       0x8000000000000010, 0xC000000000000000,
       0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF]
LOW = [1, 2, 3, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
       0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF]


def main():
    rng = __import__("random").Random(0xC0FFEE)
    vectors = []
    seen = set()
    per_tag = {}

    def add(dividend_limbs, divisor_limbs, tag, budget=12):
        u = to_int(dividend_limbs)
        v = to_int(divisor_limbs)
        if u < v:
            # Public big_uint::div_rem short-circuits dividend < divisor
            # (`return {zero, *this}` in cpp/src/bigint.cpp) before
            # div_rem_knuth runs, so the case deterministically trips no
            # Algorithm D branch in the C++ port. Tag it `smalldiv` with
            # an empty branch set (still budgeted against the requested
            # tag so the family's row distribution is unchanged).
            eff_tag = "smalldiv"
            branches = []
        else:
            eff_tag = tag
            branches = check(dividend_limbs, divisor_limbs)
            for claim in tag.split("+"):
                if claim in ("clamp", "rbreak", "addback"):
                    assert claim in branches, \
                        f"tag {tag!r} claims branch {claim!r} but got {sorted(branches)}"
            if tag == "shift0":
                assert countl_zero(divisor_limbs[-1]) == 0
            elif tag == "lowlimb0":
                assert divisor_limbs[0] == 0
        key = (hexs(dividend_limbs), hexs(divisor_limbs))
        if key in seen or per_tag.get(tag, 0) >= budget:
            return
        seen.add(key)
        per_tag[tag] = per_tag.get(tag, 0) + 1
        q_int, r_int = divmod(u, v)
        vectors.append((key[0], key[1], int_hex(q_int), int_hex(r_int),
                        eff_tag, sorted(branches)))

    def add_search(gen, tag, budget=12):
        for u, d, extra in gen():
            add(u, d, tag, budget)

    # --- random smoke first: validates the simulator against the oracle ---
    for _ in range(1000):
        n = rng.randint(2, 6)
        m = rng.randint(1, 4)
        divisor = [rng.randrange(BASE) for _ in range(n)]
        divisor[n - 1] |= 1 << 63
        u = from_int(rng.randrange(BASE ** (m + n - 1), BASE ** (m + n)), m + n)
        check(u, divisor)
    print("# random smoke: 1000 cases ok", flush=True)

    # --- family 1: divisor top limb already normalised (shift == 0) ---
    def f1():
        for top in (0x8000000000000000, 0x8000000000000001, 0xFFFFFFFFFFFFFFFF):
            for low in (0, 1, 0xFFFFFFFFFFFFFFFF):
                v = [low, top]
                for q in (0, 1, 0xFFFFFFFFFFFFFFFF):
                    for r in (0, 1, top - 1, top):
                        yield from_int(q * to_int(v) + r, len(v) + 1), v, "shift0"
    add_search(f1, "shift0")

    # --- family 2: divisor low limb zero, top limb high bit set ---
    def f2():
        for top in (0x8000000000000000, 0xFFFFFFFFFFFFFFFF):
            v = [0, top]
            for q in (1, 0x1000000000000000, 0xFFFFFFFFFFFFFFFF):
                for r in (0, 1, top - 1):
                    yield from_int(q * to_int(v) + r, len(v) + 2), v, "lowlimb0"
    add_search(f2, "lowlimb0")

    # --- family 3: q_hat >= BASE clamp (+ r_hat >= BASE break) ---
    # The clamp fires when a running remainder's top limb reaches the
    # divisor's top limb (window / divisor_hi >= BASE), which can only
    # happen at a digit below the most significant one. Structured search,
    # emitting only vectors whose branch trace actually contains 'clamp'.
    def f3():
        for n in (2, 3):
            for dtop in TOP:
                if dtop < 0x8000000000000000:
                    continue
                for dlow in (1, 2, 0xFFFFFFFFFFFFFFFF):
                    d = [dlow, dtop] + [dtop] * (n - 2)
                    for m in (2, 3):
                        for utop in (dtop, 0xFFFFFFFFFFFFFFFF):
                            for mid in (0, 1, dtop - 1, dtop, 0xFFFFFFFFFFFFFFFF):
                                for low in (0, 1, 0xFFFFFFFFFFFFFFFF):
                                    u = [low] * (n + m)
                                    u[m + n - 1] = utop
                                    u[m + n - 2] = mid
                                    branches = check(u, d)
                                    if "clamp" in branches:
                                        yield u, d, "clamp"
    add_search(f3, "clamp", budget=14)

    # --- family 4: D6 add-back, and the clamp+rbreak+addback triple ---
    # For n == 2 the second D3 test is exactly the add-back test, so the
    # add-back is only reachable for n >= 3. Pure add-back vectors (no
    # clamp) are emitted first; the clamp+rbreak+addback triples follow
    # under their own tag so both flavours are pinned.
    pure_addback = []
    triples = []
    for d2 in TOP:
        if d2 < 0x8000000000000000:
            continue
        for d1 in (0x8000000000000000, 0xFFFFFFFFFFFFFFFF):
            for d0 in LOW:
                d = [d0, d1, d2]
                for u3 in (0, 1, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF):
                    for u2 in (0, 1, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF):
                        for u1 in (0, 1, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF):
                            u = [0, u1, u2, u3]
                            branches = check(u, d)
                            if "addback" not in branches:
                                continue
                            if "clamp" in branches and "rbreak" in branches:
                                triples.append((u, d))
                            elif "clamp" not in branches:
                                pure_addback.append((u, d))
    for u, d in pure_addback:
        add(u, d, "addback", budget=8)
    for u, d in triples:
        add(u, d, "addback+clamp+rbreak", budget=6)

    # --- family 5: dividends at exact / near multiples ---
    def f5():
        for nlimbs in (2, 3):
            divisor = [0x123456789ABCDEF0, 0x8000000000000000]
            while len(divisor) < nlimbs:
                divisor.append(0x8000000000000000)
            base_q = 1 << (64 * (nlimbs + 1))
            for q in (base_q - 1, base_q, base_q + 1, base_q - 2):
                for r in (0, 1, to_int(divisor) - 1):
                    yield from_int(q * to_int(divisor) + r, nlimbs + 2), divisor, "nearmultiple"
    add_search(f5, "nearmultiple")

    # --- emit ---
    lines = [
        "// Auto-generated by `cpp/scripts/gen_algod_vectors.py` — do not edit.",
        "// Rows are (dividend, divisor, expected quotient, expected remainder,",
        "// tag, branches); q and r are the exact Euclidean quotient/remainder",
        "// from an independent Python-int oracle (u == q*v + r, 0 <= r < v),",
        "// cross-checked against this Algorithm D port at generation time.",
        "// `tag` names the branch(es) the case deterministically trips through",
        "// the public div_rem dispatch:",
        "//   clamp       D3 `q_hat >= BASE` (min(q_hat, b-1)) clamp",
        "//   rbreak      D3 break after `r_hat += divisor_hi` overflows",
        "//   addback     D6 single add-back after an over-estimated digit",
        "//   shift0      D1 normalisation shift == 0 (top bit already set)",
        "//   lowlimb0    divisor low limb is zero",
        "//   nearmultiple  dividend is an exact / near multiple of the divisor",
        "//   smalldiv    dividend < divisor: public div_rem returns {0, n}",
        "//               and div_rem_knuth never runs (no D branch tripped)",
        "// `branches` is the '+' -joined full branch set the mirror recorded",
        "// for the case (a superset of `tag` where D branches apply; empty",
        "// for smalldiv).",
    ]
    for dh, vh, qh, rh, tag, branches in vectors:
        lines.append(f'    {{"{dh}", "{vh}", "{qh}", "{rh}", "{tag}", "{chr(43).join(branches)}"}},')

    out = "\n".join(lines)
    print()
    print(out)
    print(f"\n# {len(vectors)} vectors emitted")
    counts = {}
    for _, _, _, _, tag, _ in vectors:
        counts[tag] = counts.get(tag, 0) + 1
    print(counts)


if __name__ == "__main__":
    main()
