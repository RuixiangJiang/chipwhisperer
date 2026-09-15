import time
import chipwhisperer as cw

CLKGEN_FREQ = 7372800
BAUD = 115200

def payload_bytes(x):
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    if hasattr(x, "to_bytes"):
        try:
            return bytes(x)
        except Exception:
            pass
    if isinstance(x, str):
        return x.encode("latin-1", errors="replace")
    return bytes(x)

def reset_target(scope, delay=1.5):
    scope.io.nrst = "low"
    time.sleep(0.1)
    scope.io.nrst = "high_z"
    time.sleep(delay)

scope = cw.scope()
scope.default_setup()

scope.clock.clkgen_freq = CLKGEN_FREQ
scope.clock.adc_src = "clkgen_x4"

scope.io.hs2 = "clkgen"
scope.io.tio1 = "serial_rx"
scope.io.tio2 = "serial_tx"

scope.trigger.triggers = "tio4"
scope.adc.basic_mode = "rising_edge"
scope.adc.samples = 5000
scope.adc.timeout = 0.5

target = cw.target(scope, cw.targets.SimpleSerial2)
try:
    target.ser.baud(BAUD)
except Exception:
    pass

reset_target(scope)
target.flush()

# ping first
target.simpleserial_write("P", bytearray([]))
p = target.simpleserial_read_witherrors("P", 1, glitch_timeout=2.0)
print("P response:", p)

target.flush()
scope.arm()
target.simpleserial_write("H", bytearray([]))
cap_timeout = scope.capture()
resp = target.simpleserial_read_witherrors("H", 4, glitch_timeout=5.0)

payload = payload_bytes(resp.get("payload") if isinstance(resp, dict) else None)
h = int.from_bytes(payload, "little") if len(payload) == 4 else None

print("H response:", resp)
print("capture_timeout:", cap_timeout)
print("trigger_count:", scope.adc.trig_count)
print("h:", h, hex(h) if h is not None else None)

target.dis()
scope.dis()
