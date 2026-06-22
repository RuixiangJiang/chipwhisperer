import time
import chipwhisperer as cw
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, DEFAULT_BAUD

def reset_target(scope):
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.5)

def make_target(scope, baud):
    target = cw.target(scope, cw.targets.SimpleSerial2)
    try:
        target.baud = baud
    except Exception as e:
        print("target.baud set warning:", repr(e))
    try:
        target.ser.baud = baud
    except Exception as e:
        print("target.ser.baud set warning:", repr(e))
    return target

scope = cw.scope()
scope.default_setup()

scope.clock.clkgen_freq = CLKGEN_FREQ
scope.clock.adc_src = ADC_SRC
scope.io.hs2 = HS2_NORMAL
time.sleep(0.3)

print("===== actual clock =====")
print("clkgen_freq:", scope.clock.clkgen_freq)
print("clkgen_div:", scope.clock.clkgen_div)
print("adc_src:", scope.clock.adc_src)
print("adc_freq:", scope.clock.adc_freq)
print("hs2:", scope.io.hs2)

for baud in [4800, 9600, 14400, 19200, 28800, 38400, 57600, 76800, 115200]:
    print(f"\n===== baud={baud} =====")

    target = make_target(scope, baud)
    reset_target(scope)
    time.sleep(0.2)

    try:
        target.flush()
        target.flush()
    except Exception:
        pass

    # Try P, N, K. Some firmware versions may not include P.
    for cmd, rlen in [("P", 1), ("N", 4), ("K", 1)]:
        try:
            print(f"--- cmd {cmd} ---")
            target.flush()
            target.simpleserial_write(cmd, bytearray([]))
            resp = target.simpleserial_read_witherrors(cmd, rlen, glitch_timeout=500)
            print(resp)
        except Exception as e:
            print("exception:", repr(e))

    try:
        target.dis()
    except Exception:
        pass

scope.dis()
