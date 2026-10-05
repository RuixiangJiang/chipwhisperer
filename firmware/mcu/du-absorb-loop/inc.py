"""Byte-level model of PQClean's incremental SHAKE256, faithful to
keccak_inc_absorb / _finalize / _squeeze, with fault hooks.
Verified: fault=None reproduces hashlib.shake_256 for 100/136/272/336/400 B."""
from kref import RC, ROT, rol, MASK

def permute_bytes(s):
    A=[int.from_bytes(s[8*i:8*i+8],'little') for i in range(25)]
    for rnd in range(24):
        C=[A[x]^A[x+5]^A[x+10]^A[x+15]^A[x+20] for x in range(5)]
        D=[C[(x+4)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(5): A[x+5*y]^=D[x]
        B=[0]*25
        for x in range(5):
            for y in range(5): B[y+5*((2*x+3*y)%5)]=rol(A[x+5*y],ROT[x][y])
        for x in range(5):
            for y in range(5): A[x+5*y]=B[x+5*y]^((~B[(x+1)%5+5*y])&B[(x+2)%5+5*y]&MASK)
        A[0]^=RC[rnd]
    for i in range(25): s[8*i:8*i+8]=A[i].to_bytes(8,'little')

R=136
class Ctx:
    def __init__(self): self.s=bytearray(200); self.n=0; self.perms=0

def absorb(c, m, fault=None):
    """fault = ('outer', k)    -> loop-back branch skipped after block k
               ('inner', k, j) -> inner byte loop in block k stops after j bytes"""
    mlen=len(m); off=0; blk=0
    while mlen + c.n >= R:
        cnt = R - c.n
        lim = min(fault[2], cnt) if (fault and fault[0]=='inner' and fault[1]==blk) else cnt
        for i in range(lim): c.s[c.n+i] ^= m[off+i]
        mlen -= cnt; off += cnt; c.n = 0
        permute_bytes(c.s); c.perms += 1
        blk += 1
        if fault and fault[0]=='outer' and fault[1]==blk: break
    for i in range(mlen): c.s[c.n+i] ^= m[off+i]
    c.n += mlen

def finalize(c, p=0x1F):
    c.s[c.n] ^= p; c.s[R-1] ^= 0x80; c.n = 0

def squeeze(c, outlen):
    out=b''
    while outlen>0:
        permute_bytes(c.s); c.perms += 1
        k=min(outlen,R); out+=bytes(c.s[:k]); outlen-=k; c.n=R-k
    return out

def run(m, outlen=64, fault=None):
    c=Ctx(); absorb(c,m,fault); finalize(c); return squeeze(c,outlen), c.perms
