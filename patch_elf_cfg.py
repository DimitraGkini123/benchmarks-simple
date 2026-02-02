# patch_elf_cfg.py
import struct
import subprocess
from pathlib import Path

ELF_IN  = Path("build/lp_inj_patched.elf")
ELF_OUT = Path("build/lp_inj_cfgON.elf")
BIN     = Path("attested_cfg.bin")
SECTION = ".attested_cfg"

def get_section_info(elf: Path, section: str):
    # Read: idx name size vma lma fileoff align
    cmd = ["arm-none-eabi-objdump", "-h", str(elf)]
    txt = subprocess.check_output(cmd, text=True, errors="replace")

    for line in txt.splitlines():
        line = line.strip()
        if not line or section not in line:
            continue
        # Example:
        #  2 .attested_cfg 00000014  10007900  10007900  00008900  2**8
        parts = line.split()
        # parts: [idx, name, size, vma, lma, fileoff, align]
        if len(parts) >= 7 and parts[1] == section:
            size = int(parts[2], 16)
            fileoff = int(parts[5], 16)
            align = parts[6]
            return size, fileoff, align

    raise RuntimeError(f"section {section} not found in {elf}")

def main():
    if not ELF_IN.exists():
        raise FileNotFoundError(f"missing {ELF_IN}")
    if not BIN.exists():
        raise FileNotFoundError(f"missing {BIN}")

    data = BIN.read_bytes()
    sec_size, fileoff, align = get_section_info(ELF_IN, SECTION)

    if len(data) != sec_size:
        raise RuntimeError(f"bin size {len(data)} != section size {sec_size}")

    elf_bytes = bytearray(ELF_IN.read_bytes())
    elf_bytes[fileoff:fileoff+sec_size] = data

    ELF_OUT.write_bytes(elf_bytes)

    print(f"patched {ELF_OUT.name} at fileoff 0x{fileoff:x} ({SECTION}, {sec_size} bytes, {align})")
    print("bytes:", data.hex())

if __name__ == "__main__":
    main()
