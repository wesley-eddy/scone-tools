from bcc import BPF
from bcc.utils import printb
import ctypes as ct

import signal
import sys
import time
import os

device = sys.argv[1]
if len(sys.argv) != 2:
    print("Usage: %s <ifdev>" % sys.argv[0])
    exit(1)

b = BPF(src_file="scone_modifier_ebpf.c") # pyright: ignore[reportArgumentType]
fn = b.load_func("modify_scone_ebpf", BPF.XDP)
print(f"  Attaching modifier for incoming packets on device {device}.")
print("Attach:", b.attach_xdp(device, fn, BPF.XDP_FLAGS_SKB_MODE))

def signal_handler(sig, frame):
    b.remove_xdp(device, 0)
    print(f"Detached from {device}.")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

config = b.get_table("scone_rate")
rate = 1

while True:
    config[ct.c_int(0)] = ct.c_ubyte(rate)
    print(f"Current rate: {rate} ({f'{0.1*10**(rate/20)} Mbps/{0.0125*10**(rate/20)} MBps' if rate < 127 else 'No limit'})")
    rate = int(input((f"New rate (Ctrl-C to stop): ")))
    if rate < 0: rate = 0
    if rate > 127: rate = 127
