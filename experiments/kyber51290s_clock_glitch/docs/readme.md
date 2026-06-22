### Parameter set 1:

[width=8, offset=-16, repeat=2, ext_offset=2402].

Using host-generated Kyber512-90s ciphertexts and a decoder-triggered clock glitch at width=8, offset=-16, repeat=2, ext_offset=2402, the target produced 69 normal_wrong_ss responses out of 1000 trials, with 927 normal_correct responses and 4 crashes. This confirms that the decoder fault oracle remains reproducible under host-side ciphertext generation.

The glitch setting is strongly localized to:

bit_index = 208
byte      = 26
bit       = 0

This corresponds to msg[26] bit 0 in poly_tomsg().

However, the current fault behaves like a direct corruption of the decoded message bit or byte-update logic, rather than a selective skip of the `+KYBER_Q/2` threshold-bias term.

Conclusion: successfully target msg[26], but not target the correct operation `+KYBER_Q/2`.

In the software-injected skip experiment, the firmware deliberately omitted the +KYBER_Q/2 term for msg[26] bit 0 in poly_tomsg(). Over 10,000 no-glitch trials, 4,923 outputs differed from the host reference, and all 4,923 were clean single-bit208 flips. Among these single-bit208 faults, all samples had negative residuals: 2,484/2,484 for m_bit=0 and 2,439/2,439 for m_bit=1. This confirms that the bit index, residual reconstruction, and secret-dependent inequality pipeline are internally consistent. Therefore, the earlier hardware-glitch experiments failed because the observed hardware faults did not implement the residual-selective +KYBER_Q/2 skip model.