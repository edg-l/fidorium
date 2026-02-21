#!/usr/bin/env python3
import struct, os

DEV = "/dev/hidraw0"
nonce = bytes([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])

# CID=0xFFFFFFFF, CMD=INIT|0x80=0x86, BCNT=8, nonce, zero-pad to 64
pkt = struct.pack(">IBH", 0xFFFFFFFF, 0x86, 8) + nonce
pkt += bytes(64 - len(pkt))

fd = os.open(DEV, os.O_RDWR)
os.write(fd, pkt)
print(f"Sent {len(pkt)}b, waiting...")

resp = os.read(fd, 64)
cid    = struct.unpack_from(">I", resp, 0)[0]
cmd    = resp[4] & 0x7F
bcnt   = struct.unpack_from(">H", resp, 5)[0]
echo   = resp[7:15]
newcid = struct.unpack_from(">I", resp, 15)[0]
proto  = resp[19]
caps   = resp[23]

print(f"CID:      {cid:#010x}  (expect 0xffffffff)")
print(f"CMD:      {cmd:#04x}      (expect 0x06 = INIT)")
print(f"BCNT:     {bcnt}         (expect 17)")
print(f"Nonce OK: {echo == nonce}")
print(f"New CID:  {newcid:#010x}")
print(f"Proto:    {proto}         (expect 2)")
print(f"Caps:     {caps:#04x}      (expect 0x0c)")
os.close(fd)
