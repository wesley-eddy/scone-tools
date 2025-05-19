from bcc import BPF
from bcc.utils import printb

import signal
import sys
import time

device = sys.argv[1]
operation = sys.argv[2]

b = BPF(src_file="scone_ebpf.c")
fn = b.load_func(operation, BPF.XDP)
print(f"  Attaching SCONE packets to QUIC on device {device}.")
b.attach_xdp(device, fn, 0)

def signal_handler(sig, frame):
    print("Getting counters.")
    dist = b.get_table("counters")
    print(f"   {len(dist.items())} counters.")
    for k, v in dist.items():
        print("TYPE : %10d, COUNT : %10d" % (k.value, v.value))
    print("")
    dist = b.get_table("ports")
    for k, v in dist.items():
        print("PORT : %10d, COUNT : %10d" % (k.value, v.value))

    b.remove_xdp(device, 0)
    print(f"Detached from {device}.")

signal.signal(signal.SIGINT, signal_handler)

while True:
    time.sleep(1)
