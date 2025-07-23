#!/bin/bash
#
# Demonstration script for basic SCONE testing:
# - Creates a number of network namespaces and connects them (see diagram
#   below).
# - Installs eBPF modules to add, modify, or remove SCONE packets to UDP
#   datagrams with other QUIC packets to/from specific ports.
# - Starts QUIC transfers on different ports in order to generate test
#   traffic.
# - Collects PCAP captures for analysis.
# - Prints summary information.
#
# +------+       +------+    +------+       +-----+
# | USER +<----->+ CSP1 +<-->+ CSP2 +<----->+ CAP |
# +------+       +------+    +------+       +-----+
# client  ^     ^        ^  ^        ^     ^
# packet  |     |        |  |        |     |
#   flow  |     |        |  |        |     |  server
#    >====|====>A===========>M============>R  packet
#         |              |           |        flow
#         R<============M<==========A<========<
#
# A: SCONE added
# M: SCONE modified
# R: SCONE removed
#
# Plans / TODO:
# - Add traffic limiting (tc) to a specific rate, and make the SCONE
#   signal correspond.
# - Add ABR video traffic.

SCONE_USER_NS=SCONE_USER
SCONE_CSP1_NS=SCONE_CSP1
SCONE_CSP2_NS=SCONE_CSP2
SCONE_CAP_NS=SCONE_CAP

USER_CSP_LINK=veth-user-csp
CSP_USER_LINK=veth-csp-user
CSP_CSP_1_LINK=veth-csp1-csp2
CSP_CSP_2_LINK=veth-csp2-csp1
CSP_CAP_LINK=veth-csp-cap
CAP_CSP_LINK=veth-cap-csp

USER_IP=10.0.11.1
CSP1_IP1=10.0.11.2
CSP1_IP2=10.0.21.1
CSP2_IP1=10.0.21.2
CSP2_IP2=10.0.31.1
CAP_IP=10.0.31.2

# IPv6 addresses
USER_IPV6=2001:db8:11::1
CSP1_IPV6_1=2001:db8:11::2
CSP1_IPV6_2=2001:db8:21::1
CSP2_IPV6_1=2001:db8:21::2
CSP2_IPV6_2=2001:db8:31::1
CAP_IPV6=2001:db8:31::2

PLAIN_UDP_PORT=10000
NON_SCONE_PORT=20000
SCONE_PORT=60000

# hq wants to use /tmp/logs.
mkdir -p /tmp/logs


# Create and connect network namespaces.
echo "=== Creating network namespaces."
echo "  Creating namespaces."
ip netns add $SCONE_USER_NS
ip netns add $SCONE_CSP1_NS
ip netns add $SCONE_CSP2_NS
ip netns add $SCONE_CAP_NS
echo "  Enabling IPv4 and IPv6 forwarding."
ip netns exec $SCONE_USER_NS sysctl -q -w net.ipv4.ip_forward=1
ip netns exec $SCONE_CSP1_NS sysctl -q -w net.ipv4.ip_forward=1
ip netns exec $SCONE_CSP2_NS sysctl -q -w net.ipv4.ip_forward=1
ip netns exec $SCONE_CAP_NS sysctl -q -w net.ipv4.ip_forward=1
ip netns exec $SCONE_USER_NS sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec $SCONE_CSP1_NS sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec $SCONE_CSP2_NS sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec $SCONE_CAP_NS sysctl -q -w net.ipv6.conf.all.forwarding=1
echo "  Creating virtual links."
ip -n $SCONE_USER_NS link add name $USER_CSP_LINK type veth peer netns $SCONE_CSP1_NS name $CSP_USER_LINK
ip -n $SCONE_CSP1_NS link add name $CSP_CSP_1_LINK type veth peer netns $SCONE_CSP2_NS name $CSP_CSP_2_LINK
ip -n $SCONE_CSP2_NS link add name $CSP_CAP_LINK type veth peer netns $SCONE_CAP_NS name $CAP_CSP_LINK
echo "  Assigning IPv4 and IPv6 addresses and bringing up interfaces."
ip -n $SCONE_USER_NS address add $USER_IP/30 dev $USER_CSP_LINK
ip -n $SCONE_CSP1_NS address add $CSP1_IP1/30 dev $CSP_USER_LINK
ip -n $SCONE_CSP1_NS address add $CSP1_IP2/30 dev $CSP_CSP_1_LINK
ip -n $SCONE_CSP2_NS address add $CSP2_IP1/30 dev $CSP_CSP_2_LINK
ip -n $SCONE_CSP2_NS address add $CSP2_IP2/30 dev $CSP_CAP_LINK
ip -n $SCONE_CAP_NS address add $CAP_IP/30 dev $CAP_CSP_LINK
ip -n $SCONE_USER_NS address add $USER_IPV6/64 dev $USER_CSP_LINK
ip -n $SCONE_CSP1_NS address add $CSP1_IPV6_1/64 dev $CSP_USER_LINK
ip -n $SCONE_CSP1_NS address add $CSP1_IPV6_2/64 dev $CSP_CSP_1_LINK
ip -n $SCONE_CSP2_NS address add $CSP2_IPV6_1/64 dev $CSP_CSP_2_LINK
ip -n $SCONE_CSP2_NS address add $CSP2_IPV6_2/64 dev $CSP_CAP_LINK
ip -n $SCONE_CAP_NS address add $CAP_IPV6/64 dev $CAP_CSP_LINK
ip -n $SCONE_USER_NS link set $USER_CSP_LINK up
ip -n $SCONE_CSP1_NS link set $CSP_USER_LINK up
ip -n $SCONE_CSP1_NS link set $CSP_CSP_1_LINK up
ip -n $SCONE_CSP2_NS link set $CSP_CSP_2_LINK up
ip -n $SCONE_CSP2_NS link set $CSP_CAP_LINK up
ip -n $SCONE_CAP_NS link set $CAP_CSP_LINK up
echo "  Setting IPv4 and IPv6 routes."
ip -n $SCONE_USER_NS route add $CAP_IP/32 via $CSP1_IP1
ip -n $SCONE_CSP1_NS route add $CAP_IP/32 via $CSP2_IP1
ip -n $SCONE_CSP2_NS route add $USER_IP/32 via $CSP1_IP2
ip -n $SCONE_CAP_NS route add $USER_IP/32 via $CSP2_IP2
ip -n $SCONE_USER_NS -6 route add $CAP_IPV6/128 via $CSP1_IPV6_1
ip -n $SCONE_CSP1_NS -6 route add $CAP_IPV6/128 via $CSP2_IPV6_1
ip -n $SCONE_CSP2_NS -6 route add $USER_IPV6/128 via $CSP1_IPV6_2
ip -n $SCONE_CAP_NS -6 route add $USER_IPV6/128 via $CSP2_IPV6_2
echo "  Testing IPv4 connectivity."
ip netns exec $SCONE_USER_NS ping -c 3 $CAP_IP
echo "  Testing IPv6 connectivity."
ip netns exec $SCONE_USER_NS ping6 -c 3 $CAP_IPV6
#ip -n $SCONE_USER_NS stats set dev $USER_CSP_LINK l3_stats on


# Attach eBPF programs.
echo "=== Starting eBPF SCONE programs and packet capture."
#ip netns exec $SCONE_CSP1_NS python3 scone.py $CSP_USER_LINK add_scone_ebpf & scone_pid1=$!
#ip netns exec $SCONE_CSP2_NS python3 scone.py $CSP_CSP_2_LINK modify_scone_ebpf & scone_pid2=$!
#ip netns exec $SCONE_CAP_NS python3 scone.py $CAP_CSP_LINK remove_scone_ebpf & scone_pid3=$!
ip netns exec $SCONE_CSP2_NS python3 scone.py $CSP_CAP_LINK add_scone_ebpf & scone_pid3=$!
ip netns exec $SCONE_CSP1_NS python3 scone.py $CSP_CSP_1_LINK modify_scone_ebpf & scone_pid2=$!
ip netns exec $SCONE_USER_NS python3 scone.py $USER_CSP_LINK remove_scone_ebpf & scone_pid1=$!
#ip netns exec $SCONE_CSP1_NS python3 scone.py $CSP_CSP_1_LINK remove_scone_ebpf & scone_pid2=$!
#ip netns exec $SCONE_USER_NS python3 scone.py $USER_CSP_LINK modify_scone_ebpf & scone_pid1=$!


# Capture packets.
mkdir -p pcap
ip netns exec $SCONE_USER_NS tcpdump -U -n -w pcap/user.pcap -i $USER_CSP_LINK & dump_pid1=$!
ip netns exec $SCONE_CSP1_NS tcpdump -U -n -w pcap/csp1.pcap -i $CSP_CSP_1_LINK & dump_pid2=$!
ip netns exec $SCONE_CSP2_NS tcpdump -U -n -w pcap/csp2.pcap -i $CSP_CSP_2_LINK & dump_pid3=$!
ip netns exec $SCONE_CAP_NS tcpdump -U -n -w pcap/cap.pcap -i $CAP_CSP_LINK & dump_pid4=$!
echo "  Waiting 10 seconds."
sleep 10


# Run servers.
echo "=== Starting servers."
echo "  Starting IPv4 servers."
ip netns exec $SCONE_CAP_NS nc -u -l $PLAIN_UDP_PORT & nc_pid=$!
ip netns exec $SCONE_CAP_NS ./hq --mode=server --host=$CAP_IP --port=$NON_SCONE_PORT --logtostderr=false & hqs1_pid=$!
ip netns exec $SCONE_CAP_NS ./hq --mode=server --host=$CAP_IP --port=$SCONE_PORT --logtostderr=false --h2port=7776 & hqs2_pid=$!
echo "  Starting IPv6 servers."
ip netns exec $SCONE_CAP_NS nc -u -l -6 $((PLAIN_UDP_PORT + 1)) & nc6_pid=$!
ip netns exec $SCONE_CAP_NS ./hq --mode=server --host=$CAP_IPV6 --port=$((NON_SCONE_PORT + 1)) --logtostderr=false & hqs1_ipv6_pid=$!
ip netns exec $SCONE_CAP_NS ./hq --mode=server --host=$CAP_IPV6 --port=$((SCONE_PORT + 1)) --logtostderr=false --h2port=7777 & hqs2_ipv6_pid=$!
# Note: h2port is set differently for IPv6 servers to avoid collisions.
echo "  Waiting 5 seconds."
sleep 5


# Run clients.
echo "=== Running clients."
NC_DATA=/tmp/random_nc_data
openssl rand -hex 48 >$NC_DATA
echo "  IPv4 client tests:"
echo "    Doing non-SCONE-enabled fetch (IPv4)."
ip netns exec $SCONE_USER_NS ./hq --mode=client --host=$CAP_IP --port=$NON_SCONE_PORT --path=/
sleep 2
echo "    Doing SCONE-enabled fetch (IPv4)."
ip netns exec $SCONE_USER_NS ./hq --mode=client --host=$CAP_IP --port=$SCONE_PORT --path=/
sleep 2
echo "  IPv6 client tests:"
echo "    Doing non-SCONE-enabled fetch (IPv6)."
ip netns exec $SCONE_USER_NS ./hq --mode=client --host=$CAP_IPV6 --port=$((NON_SCONE_PORT + 1)) --path=/
sleep 2
echo "    Doing SCONE-enabled fetch (IPv6)."
ip netns exec $SCONE_USER_NS ./hq --mode=client --host=$CAP_IPV6 --port=$((SCONE_PORT + 1)) --path=/
sleep 2

# Stop and cleanup.
echo "=== Cleaning up."
kill -9 $dump_pid1
kill -9 $dump_pid2
kill -9 $dump_pid3
kill -9 $dump_pid4
echo "  User network interface stats:"
#ip netns exec $SCONE_USER_NS ip stats show dev $USER_CSP_LINK
kill -9 $nc_pid
kill -9 $nc6_pid
kill -9 $hqs1_pid
kill -9 $hqs1_ipv6_pid
sleep 2
kill -9 $hqs2_pid
kill -9 $hqs2_ipv6_pid
echo "  Stopping User<-CSP1 eBPF program."
kill -2 $scone_pid1
sleep 2
echo "  Stopping CSP1<-CSP2 eBPF program."
kill -2 $scone_pid2
sleep 2
echo "  Stopping CSP2<-CAP eBPF program."
kill -2 $scone_pid3
sleep 2
ip netns del $SCONE_USER_NS
ip netns del $SCONE_CSP1_NS
ip netns del $SCONE_CSP2_NS
ip netns del $SCONE_CAP_NS
