// This contains only the modifier eBPF function, in accordance with draft 03
// This version is implemented as a tc filter, which allows it to be attached to ingress and egress.
// Using scone_modifier_tc.py, it is possible to dynamically change the advertised rate.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bcc/proto.h>

#define SCONE_VERSION 0x6f7dc0fd

// Rate we want to introduce at this point
BPF_ARRAY(scone_rate, u8, 1);

struct sconepkt
{
    u8 rate_signal : 6; // LSB first
    u8 type : 2;
    u32 version;
} __attribute__((packed));

// Borrowed from: https://gist.github.com/sbernard31/d4fee7518a1ff130452211c0d355b3f7
__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

int modify_scone_ebpf(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    struct sconepkt *quic = (void *)udp + sizeof(*udp);

    // Check length
    if ((void *)quic + sizeof(*quic) > data_end)
    {
        return TC_ACT_OK;
    }

    // Check for IPv4
    u16 ipproto = bpf_ntohs(eth->h_proto);
    if (ipproto != ETH_P_IP)
    {
        return TC_ACT_OK;
    }

    // Check for UDP
    if (ip->protocol != IPPROTO_UDP)
    {
        return TC_ACT_OK;
    }

    // Check long header
    if (!(quic->type & 2))
    {
        return TC_ACT_OK;
    }

    u32 index = 0;
    u8 *rate_ptr = (u8 *)scone_rate.lookup(&index);
    if (rate_ptr == NULL)
    {
        return TC_ACT_OK;
    }
    u8 rate = *rate_ptr;

    if ((bpf_ntohl(quic->version) & 0x7fffffff) != SCONE_VERSION)
    {
        return TC_ACT_OK;
    }

    if ((quic->rate_signal << 1) + (bpf_ntohl(quic->version) >> 31) <= rate)
    {
        return TC_ACT_OK;
    }

    quic->version = bpf_htonl(SCONE_VERSION | (0x80000000 * (rate & 0x1)));
    quic->rate_signal = rate >> 1;

    // In the TC path, we do not need to modify the checksum, as it seems to be a partial one (maybe only over the header)

    return TC_ACT_OK;
}
