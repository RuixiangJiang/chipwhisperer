import time
import chipwhisperer as cw
from kyber_clock_config import CLKGEN_FREQ, ADC_SRC, HS2_NORMAL, DEFAULT_BAUD

def reset_target(scope):
    try:
        scope.io.nrst = "low"
        time.sleep(0.05)
        scope.io.nrst = "high_z"
        time.sleep(0.3)
    except Exception as e:
        print("reset warning:", repr(e))

def make_target(scope, baud):
    try:
        return cw.target(scope, cw.targets.SimpleSerial2, baud=baud)
    except TypeError:
        target = cw.target(scope, cw.targets.SimpleSerial2)
        try:
            target.baud = baud
        except Exception:
            pass
        return target

scope = cw.scope()
scope.default_setup()

# IMPORTANT: apply our config AFTER default_setup(), otherwise default_setup overrides it.
scope.clock.clkgen_freq = CLKGEN_FREQ
scope.clock.adc_src = ADC_SRC
scope.io.hs2 = HS2_NORMAL

time.sleep(0.3)

print("===== actual clock =====")
print("CLKGEN_FREQ config:", CLKGEN_FREQ)
print("DEFAULT_BAUD config:", DEFAULT_BAUD)
print("scope.clock.clkgen_freq:", scope.clock.clkgen_freq)
print("scope.clock.clkgen_div:", scope.clock.clkgen_div)
print("scope.clock.adc_src:", scope.clock.adc_src)
print("scope.clock.adc_freq:", scope.clock.adc_freq)
print("scope.io.hs2:", scope.io.hs2)

reset_target(scope)

# Try several bauds because lowering target clock can shift UART baud.
for baud in [DEFAULT_BAUD, 38400, 19200, 9600]:
    print(f"\n===== Testing SimpleSerial2 baud={baud} =====")
    target = make_target(scope, baud)
    time.sleep(0.2)

    try:
        target.flush()
    except Exception:
        pass

    try:
        target.simpleserial_write("P", bytearray([]))
        resp = target.simpleserial_read_witherrors("P", 1, glitch_timeout=200)
        print(resp)
    except Exception as e:
        print("exception:", repr(e))

    try:
        target.dis()
    except Exception:
        pass

scope.dis()
