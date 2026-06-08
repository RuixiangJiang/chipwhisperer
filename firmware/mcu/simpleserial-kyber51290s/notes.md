# Why the Initial Kyber SimpleSerial Firmware Appeared to Fail Communication

## 1. Final status

The current ChipWhisperer Kyber512-90s firmware has been validated on CW-Lite / STM32F3 with the original pqm4 implementation.

The following tests passed:

```text
1. Firmware reset banner is visible.
2. SimpleSerial2 ping works.
3. Original pqm4 randombytes() returns successfully.
4. crypto_kem_keypair(pk, sk) returns 0.
5. The host can read the 800-byte public key from the target.
6. Target-side keypair -> encapsulation -> decapsulation succeeds.
7. Host can read a ciphertext from the target and upload it back.
8. Target decapsulation of uploaded ciphertext matches the expected shared secret.
9. The upload-ct-and-decapsulate test passed 100 consecutive trials.
```

Therefore, the base hardware, programmer, clock, UART, HAL, SimpleSerial2, pqm4 RNG, Kyber keypair, encapsulation, and decapsulation paths are all functional.

## 2. What initially looked like a communication failure

At the beginning, the Kyber firmware appeared not to respond to SimpleSerial commands. The symptoms included:

```text
Read timed out
Device did not ack
get_simpleserial_commands() failed
P command did not respond
K command did not respond
Only '\x00' was seen after reset
```

At first this looked like a low-level communication problem, such as wrong platform, wrong UART pins, wrong SimpleSerial version, or failed programming.

Later tests showed that this interpretation was incomplete.

The official `simpleserial-glitch` firmware worked correctly, and the minimal `simpleserial-pingonly.c` firmware built in the same project directory also worked correctly. This proved that the following components were not the root cause:

```text
program_target.py
cw.program_target()
CW-Lite hardware
STM32F programmer
scope.default_setup()
CWLITEARM / CW308_STM32F3 platform
UART pin mapping
target clock
target reset
ChipWhisperer HAL
SimpleSerial2 itself
```

## 3. Main cause 1: SimpleSerial2 packet stream was polluted by raw UART debug output

The first major issue was mixing raw UART debug strings with SimpleSerial2 packets inside command callbacks.

For example, using code like this inside a SimpleSerial command callback causes problems:

```c
uart_puts("rRNG_BEGIN\n");
randombytes(out + 1, 16);
uart_puts("rRNG_END\n");
simpleserial_put('N', 17, out);
```

This sends raw bytes such as:

```text
rRNG_BEGIN
rRNG_END
```

directly into the same UART stream used by SimpleSerial2.

The Python host expects a SimpleSerial2 packet, for example an `N` packet. Instead, it first sees raw characters such as `R`, `N`, `G`, `_`, etc. This causes parser warnings like:

```text
Unexpected start to command
Unexpected length
```

This is not a target crash. It is a packet framing problem.

The fix is:

```text
Do not use uart_puts() inside SimpleSerial command callbacks.
Each command callback should send exactly one main SimpleSerial response packet.
```

Reset-time banners are acceptable because they are read and flushed before sending commands.

## 4. Main cause 2: Multiple response packets were sent from one callback

Another issue was sending more than one SimpleSerial application packet from a single callback.

For example:

```c
simpleserial_put('B', 1, before);
crypto_kem_keypair(pk, sk);
simpleserial_put('K', 1, after);
return 0x00;
```

In SimpleSerial2, after a callback returns, the target also sends an ACK/error packet, usually command `e`.

Therefore the UART stream becomes:

```text
B packet
K packet
e ACK packet
```

The host-side function `simpleserial_read_witherrors("B", ...)` expects the requested packet and then the ACK. It does not expect an extra `K` packet before the ACK. This caused warnings such as:

```text
Unexpected start to command 0x4b, expected 0x65
```

Here:

```text
0x4b = 'K'
0x65 = 'e'
```

So the target had actually executed keypair and sent the `K` packet, but the host parser was expecting the ACK packet at that moment.

The fix is:

```text
One command callback should normally send one main response packet.
```

For example, the keypair command should simply do:

```c
int ret = crypto_kem_keypair(pk, sk);
out[0] = (uint8_t)ret;
simpleserial_put('K', 1, out);
return 0x00;
```

## 5. Main cause 3: ACK was read twice

In several early Python tests, the code called:

```python
result = target.simpleserial_read_witherrors("K", 1, glitch_timeout=60)
ack = target.simpleserial_wait_ack(timeout=1000)
```

This is wrong for this use case.

`simpleserial_read_witherrors()` already reads the SimpleSerial2 response and consumes the ACK. The ACK status is stored in:

```python
result["rv"]
```

Therefore calling `simpleserial_wait_ack()` again tries to read an ACK that has already been consumed. This causes a false error:

```text
Device did not ack
ACK: None
```

The target did not fail. The script read the ACK twice.

The fix is:

```python
result = target.simpleserial_read_witherrors("K", 1, glitch_timeout=60)

if result.get("valid", False):
    ret = bytes(result["payload"])[0]
```

Do not call `simpleserial_wait_ack()` after this.

## 6. Main cause 4: Timeout interpretation was initially misleading

Early scripts used short timeout values such as:

```python
target.simpleserial_wait_ack(timeout=20)
```

For ChipWhisperer SimpleSerial, these timeout values are in milliseconds, not seconds.

A timeout of 20 means 20 ms, which is too short for Kyber keypair or decapsulation on a 7.37 MHz STM32F3 target.

This made a slow or busy target appear to be non-responsive.

The fix is to use larger timeouts for Kyber operations:

```python
target.simpleserial_read_witherrors("K", 1, glitch_timeout=60)
target.simpleserial_read_witherrors("S", 33, glitch_timeout=60)
```

## 7. What was not the root cause

The following were tested and ruled out:

```text
The programming script was not the root cause.
The CW-Lite hardware was not the root cause.
The platform alias CWLITEARM was not the root cause.
The STM32F3 HAL was not the root cause.
The SimpleSerial2 target class was not the root cause.
The pqm4 randombytes() function was not ultimately broken.
The pqm4 crypto_kem_keypair() function was not ultimately broken.
The pqm4 crypto_kem_dec() function was not ultimately broken.
```

The original pqm4 `randombytes()` was tested directly through an `N` command and returned successfully:

```text
randombytes() returned: 0
```

The original pqm4 keypair was also tested and returned successfully:

```text
crypto_kem_keypair() returned: 0
```

## 8. Lessons learned for the final firmware

The final firmware should follow these rules:

```text
1. Use SimpleSerial2 consistently.
2. Do not send raw UART debug strings inside command callbacks.
3. Each command callback should send one main response packet.
4. Do not call wait_ack() after simpleserial_read_witherrors().
5. Use long enough timeouts for Kyber operations.
6. Keep reset-time UART banners only for boot debugging.
7. Keep a minimal ping-only firmware for future communication sanity checks.
8. Keep a 100-trial no-glitch regression test before starting glitch sweeps.
```

## 9. Current stable command interface

The current stable interface is:

```text
P: ping
K: target generates pk/sk
R: host reads public key chunks
E: target-side encapsulation for sanity checking
T: host reads target-generated ciphertext chunks
C: host uploads ciphertext chunks
D: target decapsulation, returning ret || shared_secret
N: original pqm4 RNG probe
```

For the actual fault-injection experiment, the essential commands are:

```text
K: generate target keypair
R: read public key
C: upload ciphertext
D: run decapsulation and return ret || shared_secret
```

The `E`, `T`, and `N` commands can remain as debug tools, but they are not required for the final attack loop.

## 10. Current verified baseline before glitching

The latest no-glitch regression test ran 100 trials of:

```text
K -> E -> T -> C -> D
```

Each trial verified that:

```text
ss_enc == ss_dec
```

All 100 trials succeeded.

This means the project is ready to move from functional validation to glitch parameter search.
