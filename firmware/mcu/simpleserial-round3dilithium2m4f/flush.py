import chipwhisperer as cw, time
scope = cw.scope(sn='50203220573555303030343235323038')
scope.default_setup()
target = cw.target(scope, cw.targets.SimpleSerial2)
target.baud = 230400
scope.io.nrst = 'low';  time.sleep(0.05)
scope.io.nrst = 'high_z'; time.sleep(0.25)
target.flush()
target.simpleserial_write('i', bytearray([]))
print(target.simpleserial_read('r', 8, timeout=1000))