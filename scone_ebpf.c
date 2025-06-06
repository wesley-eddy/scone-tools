// TODO: Only IPv4 is handled, not IPv6.
// TODO: This adds SCONE to all UDP packets that seem to have QUIC long header
//       with a known version number.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// Collection of u64 counters about observed and modified packets.
BPF_HISTOGRAM(counters, u64);
BPF_HISTOGRAM(ports, u64);
BPF_HISTOGRAM(scidlens, u64);
BPF_HISTOGRAM(dcidlens, u64);
BPF_HISTOGRAM(versions, u64);
// TODO: Remove later, this is just for recording first byte values received.
BPF_HISTOGRAM(firstbyte, u64);
const u64 TOO_SMALL_COUNTER = 0;
const u64 NOT_UDP_COUNTER = 1;
const u64 NOT_SCONE_PORT_COUNTER = 2;
const u64 NOT_QUIC_LONG_COUNTER = 3;
const u64 UNKNOWN_QUIC_VERSION = 4;
const u64 QUIC_LONG_COUNTER = 5;
const u64 OTHER_ERROR_COUNTER = 6;
const u64 SCONE_COUNTER = 7;
const u64 SCONE_ADDED_COUNTER = 8;
const u64 CONN_ID_LEN = 9;
const u64 SCONE_REMOVED_COUNTER = 10;
const u64 SCONE_MODIFIED_COUNTER = 11;

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

// This is a hard-coded destination UDP port number to add SCONE packets for.
const unsigned short SCONE_PORT = 30000;

// TODO: Redefine these to the actual SCONE values.
#define SCONE_V1 0x44443333
#define SCONE_V2 0x33334444

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
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    char *quic = (char *)udp + sizeof(*udp);
    u64 port;

    // Pass through if it's too small to be a QUIC packet.
    if ((void *)udp + sizeof(*udp) >= data_end)
        return TOO_SMALL_COUNTER;

    // Pass through if it's not an IP + UDP packet.
    if ((bpf_ntohs(eth->h_proto) != ETH_P_IP) ||
        (ip->protocol != IPPROTO_UDP)) {
        return NOT_UDP_COUNTER;
    }

    // TODO: Make configurable for client->server or server->client.
    //port = bpf_ntohs(udp->dest);
    port = bpf_ntohs(udp->source);
    ports.increment(port);

    // Pass through if the UDP destination port isn't configured for SCONE.
    if (port != SCONE_PORT)
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
            return SCONE_COUNTER;
        return UNKNOWN_QUIC_VERSION;
    }

    // If the checks made it all the way here, it's QUIC.
    return QUIC_LONG_COUNTER;
}

// This is hooked to receive all packets, so first it needs to check whether
// they are IP, UDP, and QUIC packets.  Then it can see if they have a SCONE
// packet that needs to be updated.
int add_scone_ebpf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);

    size_t lower_hdrlen = sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    u8 *quic = data + lower_hdrlen;
    u8 src_conn_id_len, dst_conn_id_len;

    u64 result = check_quic(data, data_end);
    if (result != QUIC_LONG_COUNTER) {
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
    __builtin_memmove(new_data, new_data+delta, lower_hdrlen);

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
    __builtin_memmove(&scone->dst_conn_id, dst_conn_id, QUIC_CONN_ID_LEN);

    // Fix up IP header to reflect new length.
    if ((u8*)ip + sizeof(*ip) >= new_data_end) return XDP_ABORTED;
    ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + sizeof(*scone));
    __u64 cs = ip->check = 0;
    ipv4_csum(ip, sizeof(*ip), &cs);
    ip->check = cs;

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
    if (result != SCONE_COUNTER) {
        counters.increment(result);
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    struct sconepkt *scone = (void *)udp + sizeof(*udp);

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
    if (result != SCONE_COUNTER) {
        counters.increment(result);
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);

    u8 *quic = (u8*)udp + sizeof(*udp);
    u8 src_conn_id_len, dst_conn_id_len;

    // Copy the lower headers back, overwriting the SCONE packet.
    const int lower_hdrs_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    if (data+sizeof(struct sconepkt)+lower_hdrs_len >= data_end)
        return XDP_ABORTED;
    __builtin_memmove(data+sizeof(struct sconepkt), data, lower_hdrs_len);
    // Adjust the packet length to shrink it.
    if (bpf_xdp_adjust_head(ctx, sizeof(struct sconepkt)) != 0) {
        // TODO: Some kind of error.
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }

    // Adjust IP length and checksum values.
    eth = (void *)(long)ctx->data;
    ip = (void *)eth + sizeof(*eth);
    data_end = (void *)(long)ctx->data_end;
    if ((void*)ip + sizeof(*ip) >= data_end) return XDP_ABORTED;
    ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - sizeof(struct sconepkt));
    __u64 cs = ip->check = 0;
    ipv4_csum(ip, sizeof(*ip), &cs);
    ip->check = cs;

    // Adjust UDP length and checksum values.
    udp = (void *)ip + sizeof(*ip);
    if ((void*)udp + sizeof(*udp) >= data_end) return XDP_ABORTED;
    udp->len = bpf_htons(bpf_ntohs(udp->len) - sizeof(struct sconepkt));
    udp->check = 0; // TODO: Use real checksum.

    result = SCONE_REMOVED_COUNTER;
    counters.increment(result);

    return XDP_PASS;
}
