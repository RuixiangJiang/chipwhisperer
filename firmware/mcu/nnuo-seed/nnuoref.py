"""Host model of sample_seed() + the full fault-hypothesis table.
Run this before touching hardware: it prints the reference seed and the cksum
of every fault outcome, so every device frame can be matched to a hypothesis."""
M = 1 << 32
SEED0 = 0x10000001
N, SENT = 32, 0xA5

def gen(s, n):
    out = []
    for _ in range(n):
        s = (1103515245 * s + 12345) % M
        out.append((s >> 16) & 0xFF)
    return out

def fnv(bs):
    h = 0x811C9DC5
    for b in bs:
        h ^= b
        h = (h * 16777619) % M
    return h

REF = gen(SEED0, N + 1)

if __name__ == '__main__':
    print('SEED0      = 0x%08X' % SEED0)
    print('sref[0:32] =', ' '.join(f'{b:02X}' for b in REF[:N]))
    print('sref[32]   = %02X   (only used for the shift test)' % REF[N])
    assert SENT not in REF, 'sentinel collides with a reference byte'
    assert 0x00 not in REF[:N], 'zero byte in reference'
    print('\ncksum(correct seed)   = 0x%08X   <- baseline' % fnv(REF[:N]))
    print('cksum(all 0xA5)       = 0x%08X   <- FULL_BYPASS' % fnv([SENT] * N))

    print('\n--- TRUNC@k : bytes 0..k-1 written, k..31 still sentinel ---')
    for k in range(N + 1):
        print(f'  TRUNC@{k:<2d} n_sent={N-k:<2d} cksum=0x{fnv(REF[:k] + [SENT]*(N-k)):08X}')

    print('\n--- STORE_SKIP@k : byte k alone never written ---')
    for k in range(N):
        b = REF[:N].copy(); b[k] = SENT
        print(f'  STORE_SKIP@{k:<2d} cksum=0x{fnv(b):08X}')

    print('\n--- IDX_SKIP@k : index increment skipped, tail shifted, nothing unwritten ---')
    for k in range(N):
        print(f'  IDX_SKIP@{k:<2d} n_diff={N-k:<2d} cksum=0x{fnv(REF[:k] + REF[k+1:N+1]):08X}')

    print('\n--- STORE_INC_SKIP@k : post-increment store skipped (tail shifts, byte 31 unwritten) ---')
    for k in range(N):
        b = REF[:k] + REF[k+1:N] + [SENT]
        print(f'  STORE_INC_SKIP@{k:<2d} n_diff={N-k:<2d} cksum=0x{fnv(b):08X}')
