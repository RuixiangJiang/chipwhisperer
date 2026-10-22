import sys,time
from cwcommon import connect,reboot,parse,classify,FRAME,MAGIC,SEL
_f=int(sys.argv[1]) if len(sys.argv)>1 else 0
scope,target=connect(**({'freq':_f} if _f else {}))
print('expected magic 0x%08X frame %d  phase_shift_steps=%d'%(MAGIC,FRAME,scope.glitch.phase_shift_steps))
reboot(scope,target)
for cmd in ('s','g'):
    target.flush(); time.sleep(0.05)
    try:
        target.simpleserial_write(cmd,bytearray([SEL,0,0,0]))
        rb=target.simpleserial_read('r',FRAME,timeout=2000)
    except Exception as e:
        print("cmd '%s': exc %s"%(cmd,e)); reboot(scope,target); continue
    d=parse(rb)
    print("cmd '%s': len=%-3d class=%-14s raw=%s"%(cmd,len(rb) if rb else 0,classify(d),bytes(rb).hex() if rb else None))
    if isinstance(d,dict):
        print("   cyc=%d cpi=%d lsu=%d fold=%d  hit=%d dirty=%d"%(d['cyc'],d['cpi'],d['lsu'],d['fold'],d['hit'],d['dirty']))
        print("   target GE_obs=0x%X GE_ref=0x%X  lanes obs=(%d,%d) ref=(%d,%d)  poly_ok=%d"
              %(d['ge_obs'],d['ge_ref'],d['lo'],d['hi'],d['rlo'],d['rhi'],d['poly_ok']))
        print("   target add at cycle %d  (use this as the glitch ext)"%d['cyc_at'])
    reboot(scope,target)
print("\nraw '01' len 1 = SS_ERR_CMD -> reflash.")
scope.dis()
