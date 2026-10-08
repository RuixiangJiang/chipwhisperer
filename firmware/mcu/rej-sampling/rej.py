"""Model of Dilithium Round-3 rej_uniform and the Ravi fault variants.
Verified: clean run gives ctr=256, 5 rejections, 783 bytes consumed."""
N = 256
Q = 8380417
SENTINEL = 0xA5A5A5A5
BUFLEN = 900
REJECT_AT = (10, 50, 90, 150, 200)

def make_buf(n=BUFLEN):
    b = bytearray(); x = 0x12345
    for _ in range(n // 3 + 2):
        s = len(b)//3
        x = (1103515245 * x + 12345) & 0x7FFFFF
        t = 0x7FF000 + (s & 0xFFF) if s in REJECT_AT else x
        b += bytes((t & 0xFF, (t >> 8) & 0xFF, (t >> 16) & 0xFF))
    return bytes(b[:n])

def rej_uniform(buf, len_=N, fault=None):
    a = [SENTINEL]*len_; ctr = pos = samp = acc = 0
    while ctr < len_ and pos + 3 <= len(buf):
        t  = buf[pos]; pos += 1
        t |= buf[pos] << 8; pos += 1
        t |= buf[pos] << 16; pos += 1
        t &= 0x7FFFFF
        ok = t < Q
        if fault and fault[0]=='acc' and samp==fault[1]: ok = True
        samp += 1
        if ok:
            if   fault and fault[0]=='store' and acc==fault[1]: ctr += 1
            elif fault and fault[0]=='ctr'   and acc==fault[1]: a[ctr] = t
            else: a[ctr] = t; ctr += 1
            acc += 1
    return a, ctr, pos

BUF = make_buf()
REF, REF_CTR, _ = rej_uniform(BUF)
