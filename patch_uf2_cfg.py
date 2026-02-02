import struct
from pathlib import Path

UF2_MAGIC0 = 0x0A324655
UF2_MAGIC1 = 0x9E5D5157
UF2_MAGIC2 = 0x0AB16F30
UF2_BLOCK_SIZE = 512
UF2_PAYLOAD_MAX = 476

def read_cfg(path: Path) -> bytes:
    b = path.read_bytes()
    if len(b) != 20:
        raise ValueError(f"attested_cfg.bin must be 20 bytes, got {len(b)}")
    return b

def patch_uf2(in_uf2: Path, out_uf2: Path, target_addr: int, cfg_bytes: bytes):
    data = bytearray(in_uf2.read_bytes())
    if len(data) % UF2_BLOCK_SIZE != 0:
        raise ValueError("UF2 size is not multiple of 512 bytes")

    patched = 0

    for off in range(0, len(data), UF2_BLOCK_SIZE):
        blk = data[off:off+UF2_BLOCK_SIZE]

        (magic0, magic1, flags, target, payload_size,
         block_no, num_blocks, family_id) = struct.unpack_from("<IIIIIIII", blk, 0)

        magic2 = struct.unpack_from("<I", blk, 508)[0]

        if magic0 != UF2_MAGIC0 or magic1 != UF2_MAGIC1 or magic2 != UF2_MAGIC2:
            continue  # skip junk

        if payload_size > UF2_PAYLOAD_MAX:
            continue

        # This UF2 block writes [target, target+payload_size)
        start = target
        end = target + payload_size

        if not (start <= target_addr < end):
            continue

        # offset inside this block's payload
        inside = target_addr - start

        # ensure it fits within payload
        if inside + len(cfg_bytes) > payload_size:
            raise RuntimeError(
                f"CFG crosses UF2 block boundary: block writes {hex(start)}..{hex(end)}, "
                f"cfg needs {len(cfg_bytes)} bytes at +{inside}"
            )

        payload_off = off + 32  # payload starts at byte 32 of block
        data[payload_off + inside: payload_off + inside + len(cfg_bytes)] = cfg_bytes
        patched += 1

    if patched == 0:
        raise RuntimeError("Did not find any UF2 block covering target address")

    out_uf2.write_bytes(data)
    print(f"Patched {patched} block(s). Wrote: {out_uf2}")

if __name__ == "__main__":
    # Inputs (adjust filenames if needed)
    in_uf2 = Path("build/lp_inj_patched.uf2")
    out_uf2 = Path("build/lp_inj_cfgON.uf2")
    cfg = read_cfg(Path("attested_cfg.bin"))

    target_addr = 0x10007A00  # from your print

    patch_uf2(in_uf2, out_uf2, target_addr, cfg)
