import sys
import chipwhisperer as cw
from cwcommon import HUSKY_SN
fw = sys.argv[1] if len(sys.argv) > 1 else 'roulette-CW308_STM32F4.hex'
scope = cw.scope(sn=HUSKY_SN)
scope.default_setup()
cw.program_target(scope, cw.programmers.STM32FProgrammer, fw)
scope.dis()
print('programmed', fw)
