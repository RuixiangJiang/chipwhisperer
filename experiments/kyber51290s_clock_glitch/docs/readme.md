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