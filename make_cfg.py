import struct

MAGIC = 0xC0FFEE00
enabled = 1
pattern_id = 3      # 1=MEMSCAN 3=ALU
intensity = 64
size_bytes = 4096

blob = struct.pack("<IIIII", MAGIC, enabled, pattern_id, intensity, size_bytes)

with open("attested_cfg.bin", "wb") as f:
    f.write(blob)

print(f"wrote {len(blob)} bytes:", blob.hex())
