// This contains 3 eBPF functions that can be attached to network devices:
// 1. add_scone_ebpf - attempts to insert SCONE packets into QUIC packets.
// 2. remove_scone_ebpf - attempts to remove SCONE packets from QUIC packets.
// 3. modify_scone_ebpf - rewrites SCONE rate guidance in SCONE packets.
//
// All of these only operate on designated UDP ports, controlled by the
// "SCONE_PORT" constant compiled-in..

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

// Collection of u64 counters about observed and modified packets.
BPF_HISTOGRAM(counters, u64);
BPF_HISTOGRAM(ports, u64);
BPF_HISTOGRAM(scidlens, u64);
BPF_HISTOGRAM(dcidlens, u64);
BPF_HISTOGRAM(versions, u64);

// TODO: Remove later, this is just for recording first byte values received.
BPF_HISTOGRAM(firstbyte, u64);

// These are different types of events that are tallied.
const u64 TOO_SMALL_COUNTER = 0;
const u64 NOT_UDP_COUNTER = 1;
const u64 NOT_SCONE_PORT_COUNTER = 2;
const u64 NOT_QUIC_LONG_COUNTER = 3;
const u64 UNKNOWN_QUIC_VERSION = 4;
const u64 QUIC_IPV4_LONG_COUNTER = 5;
const u64 QUIC_IPV6_LONG_COUNTER = 6;
const u64 OTHER_ERROR_COUNTER = 7;
const u64 SCONE_IPV4_COUNTER = 8;
const u64 SCONE_IPV6_COUNTER = 9;
const u64 SCONE_ADDED_COUNTER = 10;
const u64 CONN_ID_LEN = 11;
const u64 SCONE_REMOVED_COUNTER = 12;
const u64 SCONE_MODIFIED_COUNTER = 13;

// To work with the eBPF validator, packet lengths need to be checked against
// constants, so 8 bytes of connection ID is assumed here, as used by hq.
# define QUIC_CONN_ID_LEN 8 

// QUIC versions from IANA registry:
// https://www.iana.org/assignments/quic/quic.xhtml#quic-versions
// plus versions used by mvfst.
const u32 quic_versions[] = { 0x00000000, 0x00000001,
                              0x51303433, 0x51303436, 0x51303530,
                              0x6b3343cf, 0x709a50c4,
                              0xfaceb001, 0xfaceb002 };
const int NUM_QUIC_VERSIONS = 9;

// These are hard-coded destination UDP port numbers to add SCONE packets for.
const unsigned short SCONE_PORT_IPV4 = 60000;
const unsigned short SCONE_PORT_IPV6 = 60001;
const unsigned short NON_SCONE_PORT_IPV4 = 20000;
const unsigned short NON_SCONE_PORT_IPV6 = 20001;

// TODO: Redefine these to the actual SCONE values.
#define SCONE_V1 0x53434f4E
#define SCONE_V2 0x4e4f4353

struct sconepkt {
    u8 rate_signal;
    u32 version;
    u8 src_conn_id_len;
    // TODO: Testing with 0-byte destination connection IDs.
    //u8 src_conn_id[QUIC_CONN_ID_LEN];
    u8 dst_conn_id_len;
    u8 dst_conn_id[QUIC_CONN_ID_LEN];
} __attribute__((packed));
// Note: connection ID lengths and values are not included above.

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

__attribute__((__always_inline__))
static inline void ipv4_csum(void *data_start, int data_size,  __u64 *csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

// TODO: This fails verifier checks.
__attribute__((__always_inline__))
static inline void ipv4_l4_csum(void *data_start, __u32 data_size,
                                __u64 *csum, struct iphdr *iph) {
  __u32 tmp = 0;
  *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
  *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
  tmp = __builtin_bswap32((__u32)(iph->protocol));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  tmp = __builtin_bswap32((__u32)(data_size));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

// Classify the input packet to determine if it should be worked on.
static __always_inline u64 check_quic(void *data, void *data_end) {
    // First check for either IPv4 or IPv6.
    struct ethhdr *eth = data;
    u16 ipproto = bpf_ntohs(eth->h_proto);
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
    struct udphdr *udp;
    char *quic;
    u16 port;
    
    // Bounds check for Ethernet header
    if ((void *)eth + sizeof(*eth) > data_end)
        return TOO_SMALL_COUNTER;
    
    // Set UDP pointer based on IP version with proper bounds checking
    if (ipproto == ETH_P_IPV6) {
        // IPv6: Ethernet + IPv6 header + UDP header
        if ((void *)ip6 + sizeof(*ip6) + sizeof(struct udphdr) > data_end)
            return TOO_SMALL_COUNTER;
        udp = (void *)ip6 + sizeof(*ip6);
    } else {
        // IPv4: Ethernet + IPv4 header + UDP header  
        if ((void *)ip + sizeof(*ip) + sizeof(struct udphdr) > data_end)
            return TOO_SMALL_COUNTER;
        udp = (void *)ip + sizeof(*ip);
    }
    
    quic = (char *)udp + sizeof(*udp);
    
    // Pass through if it's too small to be a QUIC packet.
    if ((void*)quic >= data_end)
        return TOO_SMALL_COUNTER;

    // Pass through if it's not an IP + UDP packet.
    if (((ipproto != ETH_P_IP) || (ip->protocol != IPPROTO_UDP)) &&
        ((ipproto != ETH_P_IPV6) || (ip6->nexthdr != IPPROTO_UDP))) {
        return NOT_UDP_COUNTER;
    }

    // TODO: Make configurable for client->server or server->client.
    //port = bpf_ntohs(udp->dest);
    port = bpf_ntohs(udp->source);
    ports.increment(port);

    // Pass through if the UDP source port isn't configured for SCONE or non-SCONE testing.
    if (port != SCONE_PORT_IPV4 && port != SCONE_PORT_IPV6 && 
        port != NON_SCONE_PORT_IPV4 && port != NON_SCONE_PORT_IPV6)
        return NOT_SCONE_PORT_COUNTER;

    // TODO: Remove later, this is just for seeing what is received.
    port = quic[0];
    firstbyte.increment(port);

    // Check for QUIC packet in contents.
    if ((quic[0] & 0x80) != 0x80)
        return NOT_QUIC_LONG_COUNTER;

    // Looking deeper, check out the QUIC version number.
    if ((void*)quic + 5 > data_end)
        return NOT_QUIC_LONG_COUNTER;

    u32 quic_version = quic[1]<<24 | quic[2]<<16 | quic[3]<<8 | quic[4];
    versions.increment(quic_version);
    int known_version = 0;
    for (int i = 0; i < NUM_QUIC_VERSIONS; i++) {
        if (quic_version == quic_versions[i]) {
            known_version = 1;
            break;
        }
    }
    if (!known_version) {
        if (quic_version == SCONE_V1 || quic_version == SCONE_V2)
            return (ipproto == ETH_P_IP) ? SCONE_IPV4_COUNTER
                                         : SCONE_IPV6_COUNTER;
        return UNKNOWN_QUIC_VERSION;
    }

    // If the checks made it all the way here, it's QUIC.
    return (ipproto == ETH_P_IP) ? QUIC_IPV4_LONG_COUNTER : QUIC_IPV6_LONG_COUNTER;
}

// This is hooked to receive all packets, so first it needs to check whether
// they are IP, UDP, and QUIC packets.  Then it can see if they have a SCONE
// packet that needs to be updated.
int add_scone_ebpf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
    struct udphdr *udp;
    size_t lower_hdrlen;
    u8 *quic;
    u8 src_conn_id_len, dst_conn_id_len;

    u64 result = check_quic(data, data_end);
    if (result != QUIC_IPV4_LONG_COUNTER && result != QUIC_IPV6_LONG_COUNTER) {
        counters.increment(result);
        return XDP_PASS;
    }
    
    // Set header pointers and lengths based on IP version with bounds checking
    if (result == QUIC_IPV6_LONG_COUNTER) {
        // IPv6 packet - need to re-verify bounds for IPv6 header access
        if ((void *)ip6 + sizeof(*ip6) + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        udp = (void*)ip6 + sizeof(*ip6);
        lower_hdrlen = sizeof(*eth) + sizeof(*ip6) + sizeof(*udp);
        quic = data + lower_hdrlen;
        // Verify QUIC payload is accessible
        if (quic >= (u8*)data_end)
            return XDP_PASS;
    } else {
        // IPv4 packet  
        if ((void *)ip + sizeof(*ip) + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        udp = (void *)ip + sizeof(*ip);
        lower_hdrlen = sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
        quic = data + lower_hdrlen;
        // Verify QUIC payload is accessible
        if (quic >= (u8*)data_end)
            return XDP_PASS;
    }
    
    // Only add SCONE to SCONE-enabled ports, pass through non-SCONE test traffic
    u16 src_port = bpf_ntohs(udp->source);
    if (src_port == NON_SCONE_PORT_IPV4 || src_port == NON_SCONE_PORT_IPV6) {
        // Pass through non-SCONE test traffic without modification
        counters.increment(result);
        return XDP_PASS;
    }

    // Adjust packet length, and make room for SCONE.
    // The amount of extra space needed depends on the connection ID lengths.
    if (quic+5 >= (u8*)data_end) {
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }
    src_conn_id_len = quic[5];
    if (quic+(6+src_conn_id_len) >= (u8*)data_end) {
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }
    dst_conn_id_len = quic[6+src_conn_id_len];
    result = (u64)src_conn_id_len;
    scidlens.increment(result); 
    result = (u64)dst_conn_id_len;
    dcidlens.increment(result); 
    // If either connection ID is longer than assumed, pass on the packet.
    // TODO: Adding SCONE only works if source connection ID is 8 bytes and
    //       the destination connection ID is 0 bytes.
    if (dst_conn_id_len != QUIC_CONN_ID_LEN || src_conn_id_len != 0) {
        result = CONN_ID_LEN;
        counters.increment(result);
        return XDP_PASS;
    }
    if (quic+(7+src_conn_id_len+dst_conn_id_len) >= (u8*)data_end) {
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }

    // Do the actual packet size increase.
    int delta = sizeof(struct sconepkt);
    if (bpf_xdp_adjust_head(ctx, 0-delta) != 0) {
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }
    eth = (void*)(long)ctx->data;
    ip = (void*)eth + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) >= data_end) return XDP_ABORTED;
    // Shift the lower layer headers forward.
    u8 *new_data = (u8 *)(long)ctx->data;
    u8 *new_data_end = (u8 *)(long)ctx->data_end;
    if (new_data + lower_hdrlen > new_data_end) return XDP_ABORTED;
    if (new_data + delta + lower_hdrlen > new_data_end) return XDP_ABORTED;
    // Manual byte-by-byte copy to avoid memmove (supports both IPv4 and IPv6)
    // IPv4 headers: 14+20+8=42, IPv6 headers: 14+40+8=62
    int max_hdr_len = (result == QUIC_IPV6_LONG_COUNTER) ? 62 : 42;
    if (lower_hdrlen <= max_hdr_len && new_data + lower_hdrlen < new_data_end && new_data + delta + lower_hdrlen < new_data_end) {
        for (int i = 0; i < max_hdr_len && i < lower_hdrlen; i++) {
            new_data[i] = new_data[delta + i];
        }
    }

    // Fill in SCONE packet.
    eth = (void*)(long)ctx->data;
    ip = (void*)eth + sizeof(*eth);
    udp = (void*)ip + sizeof(*ip);
    struct sconepkt *scone = (void*)udp + sizeof(*udp);
    if ((u8*)(scone + 1) >= new_data_end) return XDP_ABORTED;
    scone->rate_signal = 0x8A;  // TODO: Random number; high bit set.
    scone->version = bpf_htonl(SCONE_V1);
    // TODO: Testing now only with 0-byte connection ID lengths.
    scone->src_conn_id_len = 0;
    //scone->src_conn_id_len = QUIC_CONN_ID_LEN;
    //__builtin_memmove(scone->src_conn_id, new_data+lower_hdrlen+6, QUIC_CONN_ID_LEN); 
    scone->dst_conn_id_len = QUIC_CONN_ID_LEN;
    if ((u8*)&(scone->dst_conn_id) + QUIC_CONN_ID_LEN >= new_data_end) return XDP_ABORTED;
    u8 *dst_conn_id = new_data + lower_hdrlen + sizeof(*scone) + 7;
    if ((u8*)dst_conn_id + QUIC_CONN_ID_LEN >= new_data_end) return XDP_ABORTED;
    // Manual copy to avoid memmove issues (QUIC_CONN_ID_LEN = 8)
    if ((u8*)&(scone->dst_conn_id[0]) + 8 < new_data_end && dst_conn_id + 8 < new_data_end) {
        scone->dst_conn_id[0] = dst_conn_id[0];
        scone->dst_conn_id[1] = dst_conn_id[1];
        scone->dst_conn_id[2] = dst_conn_id[2];
        scone->dst_conn_id[3] = dst_conn_id[3];
        scone->dst_conn_id[4] = dst_conn_id[4];
        scone->dst_conn_id[5] = dst_conn_id[5];
        scone->dst_conn_id[6] = dst_conn_id[6];
        scone->dst_conn_id[7] = dst_conn_id[7];
    }

    // Fix up IP header to reflect new length (different for IPv4 vs IPv6).
    if (result == QUIC_IPV4_LONG_COUNTER) {
        if ((u8*)ip + sizeof(*ip) >= new_data_end) return XDP_ABORTED;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + sizeof(*scone));
        __u64 cs = ip->check = 0;
        ipv4_csum(ip, sizeof(*ip), &cs);
        ip->check = cs;
    } else {
        // IPv6 case
        struct ipv6hdr *ip6 = (void*)eth + sizeof(*eth);
        if ((u8*)ip6 + sizeof(*ip6) >= new_data_end) return XDP_ABORTED;
        ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + sizeof(*scone));
        // IPv6 has no header checksum
    }

    // Fix up UDP header to reflect new length.
    if ((u8*)udp + sizeof(*udp) >= new_data_end) return XDP_ABORTED;
    udp->len = bpf_htons(bpf_ntohs(udp->len) + sizeof(*scone));

    // Update UDP checksum based on added bytes.
    s64 csum = bpf_csum_diff(0, 0, (void*)scone, sizeof(*scone), udp->check);
    udp->check = csum;

    udp->check = 0; // TODO: Get UDP checksum update working.

    result = SCONE_ADDED_COUNTER;
    counters.increment(result);

    return XDP_PASS;
}

// Read all incoming packets, see if they have SCONE packets, and modify the
// max data rate.
int modify_scone_ebpf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    u64 result = check_quic(data, data_end);

    // Ignore anything that isn't a SCONE packet.
    if (result != SCONE_IPV4_COUNTER && result != SCONE_IPV6_COUNTER) {
        counters.increment(result);
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct ipv6hdr *ip6 = (void *)ip;
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (result == SCONE_IPV6_COUNTER) udp = (void*)ip6 + sizeof(*ip6);
    struct sconepkt *scone = (void *)udp + sizeof(*udp);
    if ((void*)scone + sizeof(*scone) >= data_end) return XDP_PASS;

    // As a test, just cut the rate signal in half.
    u8 orig_rate_signal = scone->rate_signal;
    scone->rate_signal = 0x80 | ((scone->rate_signal & 0x7F)/2);

    // UDP checksum needs to be updated, if not zero.
    u16 orig = (((u16)orig_rate_signal)<<8) |
               ((scone->version & 0xFF000000)>>16);
    u16 delta_csum = ((u16*)scone)[0] + ~orig;
    udp->check = udp->check + ~delta_csum;

    result = SCONE_MODIFIED_COUNTER;
    counters.increment(result);

    return XDP_PASS;
}

// Remove any leading SCONE packet and shift the QUIC packet up.
int remove_scone_ebpf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    u64 result = check_quic(data, data_end);

    // If it doesn't look like SCONE, ignore it.
    if (result != SCONE_IPV4_COUNTER && result != SCONE_IPV6_COUNTER) {
        counters.increment(result);
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
    struct udphdr *udp;
    int lower_hdrs_len;
    
    // Set header pointers and lengths based on IP version with bounds checking
    if (result == SCONE_IPV6_COUNTER) {
        // IPv6 packet - need to re-verify bounds for IPv6 header access
        if ((void *)ip6 + sizeof(*ip6) + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        udp = (void *)ip6 + sizeof(*ip6);
        lower_hdrs_len = sizeof(*eth) + sizeof(*ip6) + sizeof(*udp);
    } else {
        // IPv4 packet
        if ((void *)ip + sizeof(*ip) + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        udp = (void *)ip + sizeof(*ip);
        lower_hdrs_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    }

    u8 *quic = (u8*)udp + sizeof(*udp);
    u8 src_conn_id_len, dst_conn_id_len;

    // Copy the lower headers back, overwriting the SCONE packet.
    if (data+sizeof(struct sconepkt)+lower_hdrs_len >= data_end)
        return XDP_ABORTED;
    // Manual byte-by-byte copy for header removal (supports both IPv4 and IPv6)
    u8 *src = (u8*)data;
    u8 *dst = (u8*)data + sizeof(struct sconepkt);
    // IPv4 headers: 14+20+8=42, IPv6 headers: 14+40+8=62
    int max_hdr_len = (result == SCONE_IPV6_COUNTER) ? 62 : 42;
    if (lower_hdrs_len <= max_hdr_len && src + lower_hdrs_len < (u8*)data_end && dst + lower_hdrs_len < (u8*)data_end) {
        for (int i = 0; i < max_hdr_len && i < lower_hdrs_len; i++) {
            dst[i] = src[i];
        }
    }
    // Adjust the packet length to shrink it.
    if (bpf_xdp_adjust_head(ctx, sizeof(struct sconepkt)) != 0) {
        // TODO: Some kind of error.
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }

    // Adjust IP length and checksum values (different for IPv4 vs IPv6).
    eth = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    
    if (result == SCONE_IPV4_COUNTER) {
        ip = (void *)eth + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) >= data_end) return XDP_ABORTED;
        ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - sizeof(struct sconepkt));
        __u64 cs = ip->check = 0;
        ipv4_csum(ip, sizeof(*ip), &cs);
        ip->check = cs;
        udp = (void *)ip + sizeof(*ip);
    } else {
        // IPv6 case
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        if ((void*)ip6 + sizeof(*ip6) >= data_end) return XDP_ABORTED;
        ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) - sizeof(struct sconepkt));
        udp = (void *)ip6 + sizeof(*ip6);
    }

    // Adjust UDP length and checksum values.
    if ((void*)udp + sizeof(*udp) >= data_end) return XDP_ABORTED;
    udp->len = bpf_htons(bpf_ntohs(udp->len) - sizeof(struct sconepkt));
    udp->check = 0; // TODO: Use real checksum.

    result = SCONE_REMOVED_COUNTER;
    counters.increment(result);

    return XDP_PASS;
}
