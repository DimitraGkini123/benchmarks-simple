import struct
from pathlib import Path

UF2_MAGIC0 = 0x0A324655
UF2_MAGIC1 = 0x9E5D5157
UF2_MAGIC2 = 0x0AB16F30
BLK = 512

def read_at(uf2_path: Path, addr: int, n: int) -> bytes:
    data = uf2_path.read_bytes()
    out = bytearray()
    for off in range(0, len(data), BLK):
        blk = data[off:off+BLK]
        if len(blk) != BLK:
            continue
        m0, m1, flags, target, payload_size, block_no, num_blocks, family = struct.unpack_from("<IIIIIIII", blk, 0)
        m2 = struct.unpack_from("<I", blk, 508)[0]
        if m0 != UF2_MAGIC0 or m1 != UF2_MAGIC1 or m2 != UF2_MAGIC2:
            continue
        if payload_size > 476:
            continue

        start = target
        end = target + payload_size
        if start <= addr < end:
            inside = addr - start
            take = min(n - len(out), payload_size - inside)
            payload = blk[32:32+payload_size]
            out += payload[inside:inside+take]
            if len(out) >= n:
                return bytes(out)

    raise RuntimeError(f"Address {hex(addr)} not found in UF2 blocks")

if __name__ == "__main__":
    uf2 = Path("build/lp_inj_cfgON.uf2")
    addr = 0x10007A00
    b = read_at(uf2, addr, 20)
    print("UF2 bytes @", hex(addr), ":", b.hex())
