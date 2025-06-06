# SCONE Tools

This is a repository for some early testing tools to work with the in-development [IETF Standard Communication with Network Elements (SCONE)](https://datatracker.ietf.org/group/scone/about/) protocol.

There are eBPF functions provided to:

1. Add SCONE packets into other QUIC packets that come into a network interface.  This is only really intended for early testing, and not longer-term use after QUIC endpoint software supporting SCONE is more available.
2. Modify SCONE packets that come into a network interface, by changing the throughput guidance.
3. Remove SCONE packets that come into a network interface.  This is to support early testing, prior to end-host QUIC stacks supporting SCONE.

## Prerequisites

Assumptions:

- This runs on Linux.  It was tested on Ubuntu 24.
- Root access is needed in order to create network namespaces and install eBPF modules.
- The test data flows use the hq application that comes from proxygen.  Directions on building this are provided below.


### Building the "hq" Application

````
    git clone https://github.com/fastfloat/fast_float.git
    cd fast_float
    mkdir build && cd build
    cmake ..
    make
    sudo make install
    cd ..

    git clone https://github.com/facebook/proxygen.git
    cd proxygen/proxygen
    ./build.sh
    cp _build/proxygen/httpserver/hq .
````

## Running Examples

There is a shell script included that:

- Creates a number of network namespaces and interconnects them.
- Installs eBPF code to add, modify, and remove SCONE packets on interfaces within the test network namespaces.
    + The code is only setup to work with SCONE on specific UDP ports, and other QUIC traffic or UDP traffic on other ports will not be impacted.
- Starts some transfers using 'hq' on different ports to generate QUIC traffic.
- Collects tcpdump PCAP captures at different points in the network.
    - You can observe 15 bytes packet size differences in UDP payloads at different points in the path, and see that the contents correspond to SCONE packets.
- Prints some counters that help to see what the SCONE eBPF code did.
