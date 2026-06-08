# ChipWhisperer Kyber512-90s Target Firmware README

## 1. Overview

This project builds a ChipWhisperer SimpleSerial2 target firmware for testing `pqm4` Kyber512-90s on a CW-Lite / STM32F3 target board.

The current firmware has been validated with the original `pqm4` implementation. It supports:

```text
crypto_kem_keypair()
crypto_kem_enc()
crypto_kem_dec()
pqm4 original randombytes()
```

The current no-glitch baseline has passed 100 consecutive trials of:

```text
K -> E -> T -> C -> D
```

where the uploaded ciphertext decapsulates to the same shared secret as the encapsulation output.

## 2. Target and implementation

Current target platform:

```text
PLATFORM=CWLITEARM
```

Equivalent hardware target:

```text
CW-Lite Arm / CW308_STM32F3
```

Current SimpleSerial version:

```text
SS_VER=SS_VER_2_1
```

Current Kyber implementation:

```text
KYBER_IMPL=m4fspeed
```

Current scheme:

```text
Kyber512-90s
```

Important sizes:

```text
CRYPTO_PUBLICKEYBYTES   = 800 bytes
CRYPTO_SECRETKEYBYTES   = 1632 bytes
CRYPTO_CIPHERTEXTBYTES  = 768 bytes
CRYPTO_BYTES            = 32 bytes
```

Current chunk sizes used by the SimpleSerial interface:

```text
PK_CHUNK = 200 bytes
CT_CHUNK = 128 bytes
```

## 3. Build

Build the current Kyber probe firmware:

```bash
make -f Makefile.kyberprobe clean PLATFORM=CWLITEARM SS_VER=SS_VER_2_1 KYBER_IMPL=m4fspeed

make -f Makefile.kyberprobe all PLATFORM=CWLITEARM SS_VER=SS_VER_2_1 KYBER_IMPL=m4fspeed 2>&1 | tee build_kyberprobe.log
```

Expected output firmware:

```text
simpleserial-kyberprobe-CWLITEARM.hex
simpleserial-kyberprobe-CWLITEARM.elf
```

Program the target board:

```bash
python program_target.py ./simpleserial-kyberprobe-CWLITEARM.hex
```

## 4. Reset banner

After reset, the firmware prints a raw UART boot banner:

```text
rKYBERPROBE_A
rKYBERPROBE_B
rKYBERPROBE_C
```

This banner is only for startup debugging. It confirms that the firmware reaches `main()`, initializes the HAL/UART/trigger, initializes buffers, and registers commands.

The raw banner should be read and flushed before sending SimpleSerial commands. Raw UART debug strings should not be printed inside command callbacks because they can interfere with SimpleSerial2 packet parsing.

## 5. Supported SimpleSerial commands

### 5.1 `P`: Ping

Purpose:

```text
Check whether SimpleSerial2 communication is working.
```

Host request:

```text
Command: P
Payload length: 0
```

Target response:

```text
Response command: P
Payload length: 1
Payload: 0x42
```

Expected result:

```text
P -> 42
```

---

### 5.2 `N`: RNG probe

Purpose:

```text
Test original pqm4 randombytes().
```

This command calls:

```c
randombytes(out + 1, 16);
```

Host request:

```text
Command: N
Payload length: 0
```

Target response:

```text
Response command: N
Payload length: 17
Payload layout:
  byte 0      : return code from randombytes()
  bytes 1-16  : 16 random bytes
```

Expected result:

```text
return code = 0
```

Example output:

```text
randombytes() returned: 0
random bytes: f19032b357f8c90aad59207ff7139422
```

This command is mainly for debugging. It is not required in the final fault-injection loop.

---

### 5.3 `K`: Keypair

Purpose:

```text
Generate a Kyber512-90s public/secret key pair on the target.
```

This command calls:

```c
crypto_kem_keypair(pk, sk);
```

The target stores the generated public key in `pk[]` and secret key in `sk[]`.

Host request:

```text
Command: K
Payload length: 0
```

Target response:

```text
Response command: K
Payload length: 1
Payload layout:
  byte 0: return code from crypto_kem_keypair()
```

Expected result:

```text
return code = 0
```

---

### 5.4 `R`: Read public key chunk

Purpose:

```text
Read the target-generated public key from pk[].
```

Host request:

```text
Command: R
Payload length: 3
Payload layout:
  byte 0: offset low byte
  byte 1: offset high byte
  byte 2: output length
```

Target response:

```text
Response command: R
Payload length: requested output length
Payload: pk[offset : offset + output length]
```

Current public key readout convention:

```text
PK length  = 800 bytes
PK chunk   = 200 bytes
Offsets    = 0, 200, 400, 600
```

Example request for the first chunk:

```text
offset = 0
length = 200
```

This command is needed because the host must obtain the target public key before generating or selecting ciphertexts.

---

### 5.5 `E`: Target-side encapsulation

Purpose:

```text
Run target-side encapsulation for sanity checking.
```

This command calls:

```c
crypto_kem_enc(ct, ss_enc, pk);
```

The target stores the generated ciphertext in `ct[]` and the encapsulated shared secret in `ss_enc[]`.

Host request:

```text
Command: E
Payload length: 0
```

Target response:

```text
Response command: E
Payload length: 33
Payload layout:
  byte 0       : return code from crypto_kem_enc()
  bytes 1-32   : ss_enc
```

Expected result:

```text
return code = 0
```

This command is useful for internal validation:

```text
K -> E -> D
```

If `ss_enc == ss_dec`, then target-side keypair, encapsulation, and decapsulation are consistent.

This command is not required in the final attack loop if ciphertexts are generated on the host.

---

### 5.6 `T`: Read ciphertext chunk

Purpose:

```text
Read the target-generated ciphertext from ct[].
```

This is mainly used after `E`, so the host can read the target-generated ciphertext and upload it back through `C`.

Host request:

```text
Command: T
Payload length: 3
Payload layout:
  byte 0: offset low byte
  byte 1: offset high byte
  byte 2: output length
```

Target response:

```text
Response command: T
Payload length: requested output length
Payload: ct[offset : offset + output length]
```

Current ciphertext readout convention:

```text
CT length  = 768 bytes
CT chunk   = 128 bytes
Offsets    = 0, 128, 256, 384, 512, 640
```

This command is mainly for debugging and validation.

---

### 5.7 `C`: Upload ciphertext chunk

Purpose:

```text
Upload a ciphertext chunk from the host to the target.
```

The uploaded data is copied into the target-side `ct[]` buffer.

Host request:

```text
Command: C
Payload length: 130
Payload layout:
  byte 0       : offset low byte
  byte 1       : offset high byte
  bytes 2-129  : ciphertext chunk, 128 bytes
```

Target response:

```text
Response command: C
Payload length: 1
Payload layout:
  byte 0: status code
```

Expected result:

```text
status code = 0
```

Current upload convention:

```text
CT length  = 768 bytes
CT chunk   = 128 bytes
Offsets    = 0, 128, 256, 384, 512, 640
```

This command is essential for the fault-injection experiment because the host must be able to send selected ciphertexts to the target.

---

### 5.8 `D`: Decapsulation

Purpose:

```text
Run decapsulation on the target using the current ct[] and sk[].
```

This command calls:

```c
crypto_kem_dec(ss_dec, ct, sk);
```

The target returns the decapsulation return code and the resulting shared secret.

Host request:

```text
Command: D
Payload length: 0
```

Target response:

```text
Response command: S
Payload length: 33
Payload layout:
  byte 0       : return code from crypto_kem_dec()
  bytes 1-32   : ss_dec
```

Expected no-glitch result:

```text
return code = 0
ss_dec == expected shared secret
```

This command is the main command for the fault-injection experiment. The trigger currently wraps the full decapsulation call:

```c
trigger_high();
int ret = crypto_kem_dec(ss_dec, ct, sk);
trigger_low();
```

Later, the trigger window can be narrowed to `indcpa_dec()` or `poly_tomsg()`.

## 6. Recommended no-glitch test flow

The current regression test uses:

```text
K -> E -> T -> C -> D
```

Detailed flow:

```text
1. K: target generates pk/sk.
2. E: target encapsulates using pk and stores ct, returns ss_enc.
3. T: host reads the generated ct from target.
4. C: host uploads the same ct back to target.
5. D: target decapsulates uploaded ct using sk and returns ss_dec.
6. Host checks ss_enc == ss_dec.
```

The current baseline passed 100 consecutive trials:

```text
SUCCESS: uploaded ct decapsulation matches ss_enc
```

A 100/100 no-glitch pass rate should be maintained before starting glitch parameter sweeps.

## 7. Final fault-injection interface

For the final fault-injection experiment, the essential commands are:

```text
K: target generates pk/sk
R: host reads pk
C: host uploads selected ct
D: target decapsulates ct and returns ret || ss_dec
```

The host-side experimental loop should eventually become:

```text
1. K: generate target keypair.
2. R: read public key.
3. Host generates or selects ciphertext.
4. C: upload ciphertext.
5. D: run target decapsulation under glitch.
6. Classify result:
   - timeout / crash
   - ret != 0
   - ss_dec == expected ss
   - ss_dec != expected ss
```

## 8. Important SimpleSerial2 rules

The firmware should follow these rules:

```text
1. Do not print raw UART debug strings inside command callbacks.
2. Each command callback should send one main SimpleSerial response packet.
3. Do not call wait_ack() after simpleserial_read_witherrors().
4. Use long timeouts for Kyber commands.
5. Flush the target before sending a new command.
```

Correct host-side pattern:

```python
target.flush()
target.simpleserial_write("D", bytearray([]))

result = target.simpleserial_read_witherrors(
    "S",
    33,
    glitch_timeout=60,
)

if not result.get("valid", False):
    raise RuntimeError("Invalid decapsulation response")

payload = bytes(result["payload"])
ret = payload[0]
ss_dec = payload[1:]
```

Do not do this after `simpleserial_read_witherrors()`:

```python
target.simpleserial_wait_ack(timeout=1000)
```

The ACK has already been consumed by `simpleserial_read_witherrors()`.

## 9. Useful test scripts

Recommended scripts to keep:

```text
program_target.py
test_RESET.py
test_ping.py
test_rng_probe.py
test_keypair_and_read_pk.py
test_enc_dec_probe.py
test_upload_ct_dec.py
```

Suggested usage:

```bash
python program_target.py ./simpleserial-kyberprobe-CWLITEARM.hex

python test_RESET.py
python test_ping.py
python test_rng_probe.py
python test_keypair_and_read_pk.py
python test_enc_dec_probe.py
python test_upload_ct_dec.py
```

Before fault injection, `test_upload_ct_dec.py` should pass 100/100 trials without glitching.

## 10. Next step

The current firmware is ready for coarse glitch testing around:

```c
crypto_kem_dec(ss_dec, ct, sk);
```

The first glitch stage should classify outcomes under a broad decapsulation trigger window. After finding a useful timing region, the trigger can be narrowed toward:

```text
crypto_kem_dec()
  -> indcpa_dec()
      -> poly_tomsg()
```

The eventual goal is to target the Kyber decoder / message extraction path.
