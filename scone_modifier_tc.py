from bcc import BPF
from bcc.utils import printb
import ctypes as ct
from pyroute2 import IPRoute

import signal
import sys
import time
import os

if len(sys.argv) != 3:
    print("Usage: %s <ifdev> <direction>" % sys.argv[0])
    exit(1)

device = sys.argv[1]
direction = sys.argv[2]

if direction not in ["ingress", "egress"]:
    print("Direction must be either 'ingress' or 'egress'")
    exit(1)

b = BPF(src_file="scone_modifier_ebpf_tc.c") # pyright: ignore[reportArgumentType]
fn = b.load_func("modify_scone_ebpf", BPF.SCHED_CLS)
print(f"  Attaching modifier for {direction} packets on device {device}.")

def signal_handler(sig, frame):
    os.system(f"tc filter del dev {device} {direction}")
    print(f"Detached from {device}.")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

ipr = IPRoute()

idx = ipr.link_lookup(ifname=device)[0]

try:
    ipr.tc("add", "clsact", idx)
except Exception as e:
    print("Queue discipline 'clsact' already exists. Continuing...")

ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3" if direction == "egress" else "ffff:fff2", classid=1, direct_action=True)
print(f"Successfully attached eBPF TC program to {device} {direction}.")
os.system(f"tc filter show dev {device} {direction}")
print("Press Ctrl+C to detach.")

config = b.get_table("scone_rate")
rate = 1

while True:
    #time.sleep(1)
    config[ct.c_int(0)] = ct.c_ubyte(rate)
    print(f"Current rate: {rate} ({f'{0.1*10**(rate/20)} Mbps/{0.0125*10**(rate/20)} MBps' if rate < 127 else 'No limit'})")
    rate = int(input((f"New rate (Ctrl-C to stop): ")))
    if rate < 0: rate = 0
    if rate > 127: rate = 127
