# Central clock configuration for Kyber CW-Lite experiments.
# Change this file only, then all scripts importing this config will use the same clock.

# Original working default was about 7.3728 MHz.
# For low-clock experiments, use 3.6864e6 first.
CLKGEN_FREQ = 7.3728e6

# ADC clock source. Keep x4 unless you have a reason to change it.
ADC_SRC = "clkgen_x4"

# Normal target clock output.
HS2_NORMAL = "clkgen"

# During glitch attack, hs2 should be switched to "glitch".
HS2_GLITCH = "glitch"

# UART baud may need to be reduced when target clock is reduced.
# If old setup used 38400 at 7.3728 MHz, try 19200 at 3.6864 MHz.
DEFAULT_BAUD = 115200

def apply_normal_clock(scope):
    """Configure scope for normal target clock, not glitch output."""
    scope.clock.clkgen_freq = CLKGEN_FREQ
    scope.clock.adc_src = ADC_SRC
    scope.io.hs2 = HS2_NORMAL
    return scope

def apply_glitch_clock(scope):
    """Configure clock source before routing glitch output to hs2."""
    scope.clock.clkgen_freq = CLKGEN_FREQ
    scope.clock.adc_src = ADC_SRC
    scope.io.hs2 = HS2_GLITCH
    return scope
