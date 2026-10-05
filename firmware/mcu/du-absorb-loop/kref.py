"""Keccak-f[1600] with configurable START ROUND, modelling a skipped
round-counter initialisation.  Round constants are indexed by the loop
variable exactly as the C does, so starting at round k uses RC[k..23].
Verified: start=0 reproduces hashlib.shake_256 exactly."""
MASK = (1 << 64) - 1
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
      0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
      0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
      0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
      0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]

def rol(x, n):
    n %= 64
    return x if n == 0 else ((x << n) | (x >> (64 - n))) & MASK

def permute(A, start=0, nrounds=24):
    for rnd in range(start, nrounds):
        C = [A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20] for x in range(5)]
        D = [C[(x+4) % 5] ^ rol(C[(x+1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x + 5*y] ^= D[x]
        B = [0]*25
        for x in range(5):
            for y in range(5):
                B[y + 5*((2*x + 3*y) % 5)] = rol(A[x + 5*y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1) % 5 + 5*y]) & B[(x+2) % 5 + 5*y] & MASK)
        A[0] ^= RC[rnd]
    return A

def shake256_once(msg, outlen=64, start=0):
    """SHAKE256 for msg shorter than the 136-byte rate: exactly one permutation."""
    st = bytearray(200)
    for i, b in enumerate(msg): st[i] ^= b
    st[len(msg)] ^= 0x1F
    st[135]      ^= 0x80
    A = [int.from_bytes(st[8*i:8*i+8], 'little') for i in range(25)]
    A = permute(A, start=start)
    out = b''.join(a.to_bytes(8, 'little') for a in A)
    return out[:outlen]
