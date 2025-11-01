// This contains only the modifier eBPF function, in accordance with draft 03
// Using scone_modifier.py, it is possible to dynamically change the advertised rate.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bcc/proto.h>

#define SCONE_VERSION 0x6f7dc0fd

// Rate we want to introduce at this point
BPF_ARRAY(scone_rate, u8, 1);

struct sconepkt {
    u8 rate_signal : 6; // LSB first
    u8 type : 2;
    u32 version;
} __attribute__((packed));

// Borrowed from: https://gist.github.com/sbernard31/d4fee7518a1ff130452211c0d355b3f7
__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
  int i;
  #pragma unroll
  for (i = 0; i < 4; i ++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

int modify_scone_ebpf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    struct sconepkt *quic = (void *)udp + sizeof(*udp);

    // Check length
    if ((void *)quic + sizeof(*quic) > data_end) { return XDP_PASS; }

    // Check for IPv4
    u16 ipproto = bpf_ntohs(eth->h_proto);
    if (ipproto != ETH_P_IP) { return XDP_PASS; }

    // Check for UDP
    if (ip->protocol != IPPROTO_UDP) { return XDP_PASS; }

    // Check long header
    if (!(quic->type & 2)) { return XDP_PASS; }

    u32 index = 0;
    u8 *rate_ptr = (u8*)scone_rate.lookup(&index);
    if (rate_ptr == NULL) { return XDP_PASS; }
    u8 rate = *rate_ptr;

    if ((bpf_ntohl(quic->version) & 0x7fffffff) != SCONE_VERSION) { return XDP_PASS; }
    if ((quic->rate_signal << 1) + (bpf_ntohl(quic->version) >> 31) < rate) { return XDP_PASS; }

    quic->version = bpf_htonl(SCONE_VERSION | (0x80000000 * (rate & 0x1)));
    quic->rate_signal = rate >> 1;

    // Borrowed from https://github.com/iovisor/bcc/issues/2463#issuecomment-718800510
    // Compute new UDP checksum
    u32 csum_buffer = 0;
    u16 volatile *buf = (u16 *)udp; // volatile because https://github.com/iovisor/bcc/issues/4612#issuecomment-1555029970

    udp->check = 0;

    // Compute pseudo-header checksum
    csum_buffer += (u16)ip->saddr;
    csum_buffer += (u16)(ip->saddr >> 16);
    csum_buffer += (u16)ip->daddr;
    csum_buffer += (u16)(ip->daddr >> 16);
    csum_buffer += (u16)ip->protocol << 8;
    csum_buffer += udp->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < 1480; i += 2) {
        if ((void *)(buf + 1) > data_end) {
            break;
        }
        csum_buffer += *buf;
        buf++;
    }
    if ((void *)buf + 1 <= data_end) {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(u8 *)buf;
    }

    udp->check = csum_fold_helper(csum_buffer);

    return XDP_PASS;
}
