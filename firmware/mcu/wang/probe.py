"""One unglitched run per candidate command char, raw.
Optional argument: target clock in Hz, e.g. python probe.py 14740000
"""
import sys, time
from cwcommon import connect, reboot, parse, classify, FRAME, MAGIC, SEL
_f = int(sys.argv[1]) if len(sys.argv) > 1 else 0
scope, target = connect(**({'freq': _f} if _f else {}))
print('phase_shift_steps =', scope.glitch.phase_shift_steps)
reboot(scope, target)
print('expected magic 0x%08X, frame length %d\n' % (MAGIC, FRAME))
for cmd in ('s', 'g'):
    target.flush(); time.sleep(0.05)
    try:
        target.simpleserial_write(cmd, bytearray([SEL, 0, 0, 0]))
        rb = target.simpleserial_read('r', FRAME, timeout=1000)
    except Exception as e:
        print("cmd '%s': exception %s" % (cmd, e)); reboot(scope, target); continue
    d = parse(rb)
    print("cmd '%s': len=%-3d class=%-12s raw=%s"
          % (cmd, len(rb) if rb else 0, classify(d), bytes(rb).hex() if rb else None))
    if isinstance(d, dict):
        print("          cyc=%d cpi=%d lsu=%d fold=%d ndiff=%d nset=%d "
              "bck=0x%08X ick=0x%08X"
              % (d['cyc'], d['cpi'], d['lsu'], d['fold'], d['ndiff'], d['nset'],
                 d['bck'], d['ick']))
    reboot(scope, target)
print("\nraw '01' of length 1 is an SS_ERR_CMD error frame: reflash.")
scope.dis()
