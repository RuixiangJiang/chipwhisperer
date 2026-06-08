from pathlib import Path
import sys
import time

import chipwhisperer as cw


def get_programmer(platform: str):
    """Return the ChipWhisperer programmer class for the target platform."""
    if platform in ("CWLITEARM", "CW308_STM32F3", "CWNANO") or "STM32" in platform:
        return cw.programmers.STM32FProgrammer

    if platform in ("CW303", "CWLITEXMEGA"):
        return cw.programmers.XMEGAProgrammer

    if platform in ("CWHUSKY", "CW312_SAM4S") or "SAM4S" in platform:
        return cw.programmers.SAM4SProgrammer

    raise RuntimeError(f"Unknown platform: {platform}")


def main() -> None:
    if len(sys.argv) < 2:
        raise RuntimeError("Usage: python program_target.py <firmware.hex>")

    fw_path = Path(sys.argv[1]).expanduser().resolve()

    if not fw_path.exists():
        raise FileNotFoundError(f"Firmware file not found: {fw_path}")

    platform = "CWLITEARM"

    print(f"Firmware: {fw_path}")
    print("Available ChipWhisperer devices:")
    print(cw.list_devices())

    scope = cw.scope()
    time.sleep(0.05)

    scope.default_setup()

    programmer = get_programmer(platform)

    print("Programming target...")
    cw.program_target(scope, programmer, str(fw_path))
    print("Programming finished.")

    try:
        scope.dis()
    except Exception:
        pass


if __name__ == "__main__":
    main()