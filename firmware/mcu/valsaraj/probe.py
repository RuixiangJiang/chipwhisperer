"""One unglitched run per candidate command char, raw.  Use this to find out
what the target actually accepts before blaming the harness."""
import time
from cwcommon import connect, reboot, parse, classify, FRAME, MAGIC, SEL

scope, target = connect(); reboot(scope, target)
print('expected magic 0x%08X, expected frame length %d\n' % (MAGIC, FRAME))
for cmd in ('s', 'g', 'k'):
    target.flush(); time.sleep(0.05)
    try:
        target.simpleserial_write(cmd, bytearray([SEL, 0, 0, 0]))
        rb = target.simpleserial_read('r', FRAME, timeout=1000)
    except Exception as e:
        print("cmd '%s': exception %s" % (cmd, e)); reboot(scope, target); continue
    raw = bytes(rb).hex() if rb else None
    n   = len(rb) if rb else 0
    d   = parse(rb)
    tag = classify(d)
    print("cmd '%s': len=%-3d class=%-14s raw=%s" % (cmd, n, tag, raw))
    if isinstance(d, dict):
        print("          cyc=%d cpi=%d lsu=%d fold=%d nonce_end=%d shift=0x%04X nok=%d"
              % (d['cyc'], d['cpi'], d['lsu'], d['fold'], d['nonce'], d['shift'], d['nok']))
    reboot(scope, target)
print("\nraw '01' with length 1 is an SS_ERR_CMD error frame: that char is not")
print("dispatchable on the target.  Set CMD in cwcommon.py to whichever char")
print("returned a %d-byte frame with the magic above." % FRAME)
scope.dis()
