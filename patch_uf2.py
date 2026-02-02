#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path

UF2_MAGIC0 = 0x0A324655
UF2_MAGIC1 = 0x9E5D5157
UF2_MAGIC2 = 0x0AB16F30
UF2_BLOCK_SIZE = 512

# UF2 header format:
# magic0, magic1, flags, target_addr, payload_size, block_no, num_blocks, family_id, data...
HDR_FMT = "<IIIIIIII"
HDR_SIZE = 32

def parse_hex_bytes(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("_", "")
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    if len(s) % 2 != 0:
        raise ValueError("Hex string length must be even (pairs of hex digits).")
    return bytes.fromhex(s)

def load_payload(args) -> bytes:
    if args.hex is not None:
        return parse_hex_bytes(args.hex)
    if args.infile is not None:
        return Path(args.infile).read_bytes()
    raise ValueError("Provide either --hex or --infile.")

def patch_uf2(in_path: Path, out_path: Path, patch_addr: int, patch_data: bytes):
    uf2 = in_path.read_bytes()
    if len(uf2) % UF2_BLOCK_SIZE != 0:
        raise ValueError("Input is not a valid UF2 (size not multiple of 512).")

    patched = bytearray(uf2)
    remaining = len(patch_data)
    src_off = 0

    for blk_off in range(0, len(patched), UF2_BLOCK_SIZE):
        block = patched[blk_off:blk_off + UF2_BLOCK_SIZE]
        hdr = struct.unpack_from(HDR_FMT, block, 0)

        magic0, magic1, flags, target_addr, payload_size, block_no, num_blocks, family_id = hdr
        magic2 = struct.unpack_from("<I", block, UF2_BLOCK_SIZE - 4)[0]

        if magic0 != UF2_MAGIC0 or magic1 != UF2_MAGIC1 or magic2 != UF2_MAGIC2:
            continue  # allow non-data / padding blocks

        data_off = HDR_SIZE
        data_end = data_off + payload_size
        if payload_size == 0 or data_end > UF2_BLOCK_SIZE - 4:
            continue

        # Does this UF2 block overlap our patch region?
        blk_start = target_addr
        blk_end = target_addr + payload_size

        patch_start = patch_addr + src_off
        patch_end = patch_addr + len(patch_data)

        if blk_end <= patch_start or blk_start >= patch_end:
            continue

        # overlap range
        ov_start = max(blk_start, patch_start)
        ov_end   = min(blk_end, patch_end)
        ov_len   = ov_end - ov_start
        if ov_len <= 0:
            continue

        # where inside this block's payload to write
        within = ov_start - blk_start
        # where inside patch_data to read from
        patch_within = ov_start - patch_addr

        block_data_pos = blk_off + data_off + within
        patched[block_data_pos:block_data_pos + ov_len] = patch_data[patch_within:patch_within + ov_len]

    out_path.write_bytes(patched)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="input UF2")
    ap.add_argument("--out", dest="out", required=True, help="output UF2")
    ap.add_argument("--base_flash", required=True, help="flash base address in hex, e.g. 0x10000000")
    ap.add_argument("--inject_off", required=True, help="offset from __flash_binary_start, decimal or hex (e.g. 12345 or 0x3039)")
    ap.add_argument("--hex", default=None, help="payload bytes as hex string (e.g. DEADBEEF...)")
    ap.add_argument("--infile", default=None, help="payload bytes from file")
    ap.add_argument("--max_len", type=int, default=None, help="optional max length guard")

    args = ap.parse_args()

    in_path = Path(args.inp)
    out_path = Path(args.out)

    base_flash = int(args.base_flash, 0)
    inject_off = int(args.inject_off, 0)

    data = load_payload(args)
    if args.max_len is not None and len(data) > args.max_len:
        raise ValueError(f"payload too large: {len(data)} > {args.max_len}")

    # Patch address in flash = base_flash + offset
    patch_addr = base_flash + inject_off

    patch_uf2(in_path, out_path, patch_addr, data)
    print(f"[OK] patched {len(data)} bytes at flash addr 0x{patch_addr:08X} -> {out_path}")

if __name__ == "__main__":
    main()
