from bcc import BPF
from bcc.utils import printb

import signal
import sys
import time

device = sys.argv[1]
operation = sys.argv[2]

b = BPF(src_file="scone_ebpf.c")
fn = b.load_func(operation, BPF.XDP)
print(f"  Attaching '{operation}' for incoming packets on device {device}.")
b.attach_xdp(device, fn, BPF.XDP_FLAGS_SKB_MODE)

def signal_handler(sig, frame):
    print("Getting counters.")
    print("  Result types:")
    dist = b.get_table("counters")
    for k, v in dist.items():
        print("    TYPE : %10d, COUNT : %10d" % (k.value, v.value))

    print("\n  Ports:")
    dist = b.get_table("ports")
    for k, v in dist.items():
        print("    PORT : %10d, COUNT : %10d" % (k.value, v.value))

    print("\n  First Bytes:")
    dist = b.get_table("firstbyte")
    for k, v in dist.items():
        print("    BYTE : %10d, COUNT : %10d" % (k.value, v.value))

    print("\n  QUIC Versions:")
    dist = b.get_table("versions")
    for k, v in dist.items():
        print("    VERSION : %10d, COUNT : %10d" % (k.value, v.value))

    print("\n  Connection ID Lengths:")
    if operation == "add_scone_ebpf":
        dist = b.get_table("scidlens")
        for x, y in dist.items():
            print("    SCIDLEN : %10d, COUNT : %10d" % (x.value, y.value))
        dist = b.get_table("dcidlens")
        for x, y in dist.items():
            print("    DCIDLEN : %10d, COUNT : %10d" % (x.value, y.value))
    
    b.remove_xdp(device, 0)
    print(f"Detached from {device}.")

signal.signal(signal.SIGINT, signal_handler)

while True:
    time.sleep(1)
