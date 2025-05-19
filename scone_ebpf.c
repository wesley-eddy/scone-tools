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
const int quic_versions[] = { 0x00000000, 0x00000001,
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
    u8 src_conn_id[QUIC_CONN_ID_LEN];
    u8 dst_conn_id_len;
    u8 dst_conn_id[QUIC_CONN_ID_LEN];
};
// Note: connection ID lengths and values are not included above.

// Classify the input packet to determine if it should be worked on.
static __always_inline u64 check_quic(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    char *quic = (char *)udp + sizeof(*udp);
    u64 port;

    // Pass through if it's too small to be a QUIC packet.
    if ((void *)udp + sizeof(*udp) >= data_end) {
        return TOO_SMALL_COUNTER;
    }

    // Pass through if it's not an IP + UDP packet.
    if ((bpf_ntohs(eth->h_proto) != ETH_P_IP) ||
        (ip->protocol != IPPROTO_UDP)) {
        return NOT_UDP_COUNTER;
    }

    port = ntohs(udp->dest);
    ports.increment(port);

    // Pass through if the UDP destination port isn't configured for SCONE.
    if (port != SCONE_PORT) {
        return NOT_SCONE_PORT_COUNTER;
    }

    // Check for QUIC packet in contents.
    if ((quic[0] & 0x80) != 0x80) {
        return NOT_QUIC_LONG_COUNTER;
    }

    // Looking deeper, check out the QUIC version number.
    if ((void*)quic + 5 > data_end) {
        return NOT_QUIC_LONG_COUNTER;
    }
    int quic_version = quic[1]<<24 | quic[2]<<16 | quic[3]<<8 | quic[4];
    int known_version = 0;
    for (int i = 0; i < NUM_QUIC_VERSIONS; i++) {
        if (quic_version == quic_versions[i]) {
            known_version = 1;
            break;
        }
    }
    if (!known_version) {
        return UNKNOWN_QUIC_VERSION;
    }
    if (quic_version == SCONE_V1 || quic_version == SCONE_V2) {
        return SCONE_COUNTER;
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
    size_t lower_hdrlen = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr);
    u8 *quic = data + lower_hdrlen;
    u8 src_conn_id_len, dst_conn_id_len;
    int delta;
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
    // If either connection ID is longer than assumed, pass on the packet.
    if (src_conn_id_len != QUIC_CONN_ID_LEN || dst_conn_id_len != QUIC_CONN_ID_LEN) {
        result = CONN_ID_LEN;
        counters.increment(result);
        return XDP_PASS;
    }
    if (quic+(7+src_conn_id_len+dst_conn_id_len) >= (u8*)data_end) {
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }
    delta = sizeof(struct sconepkt) + src_conn_id_len + dst_conn_id_len + 2;
    if (bpf_xdp_adjust_head(ctx, delta) != 0) {
        result = OTHER_ERROR_COUNTER;
        counters.increment(result);
        return XDP_PASS;
    }
    // Shift the lower layer headers forward.
    u8 *new_data = (u8 *)(long)ctx->data;
    u8 *new_data_end = (u8 *)(long)ctx->data_end;
    if (new_data + lower_hdrlen > new_data_end) {
        return XDP_PASS; // TODO: actually an impossible error?
    }
    if (new_data + delta + lower_hdrlen > new_data_end) {
        return XDP_PASS; // TODO: actually an impossible error?
    }
    __builtin_memmove(new_data, new_data+delta, lower_hdrlen);

    // Fill in SCONE.
    struct sconepkt *scone_hdr = (void*)(long)ctx->data;
    if ((u8*)(scone_hdr + 1) >= new_data_end) {
        return XDP_PASS; // TODO: impossible.
    }
    scone_hdr->rate_signal = 0x42;
    scone_hdr->version = SCONE_V1;
    scone_hdr->src_conn_id_len = QUIC_CONN_ID_LEN;
    __builtin_memmove(scone_hdr->src_conn_id, new_data+lower_hdrlen+6, QUIC_CONN_ID_LEN); 
    scone_hdr->dst_conn_id_len = QUIC_CONN_ID_LEN;
    __builtin_memmove(scone_hdr->dst_conn_id, new_data+lower_hdrlen+7+QUIC_CONN_ID_LEN, QUIC_CONN_ID_LEN); 

    result = SCONE_ADDED_COUNTER;
    counters.increment(result);

    return XDP_PASS;
}

// Read all incoming packets, see if they have SCONE packets, and modify the
// max data rate.
int modify_scone_ebpf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    size_t lower_hdrlen = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr);
    struct sconepkt *scone = data + lower_hdrlen;
    u64 result = check_quic(data, data_end);

    if (result != SCONE_COUNTER) {
        counters.increment(result);
        return XDP_PASS;
    }

    // As a test, just cut the rate signal in half.
    scone->rate_signal /= 2;

    result = SCONE_MODIFIED_COUNTER;
    counters.increment(result);

    return XDP_PASS;
}

// Remove any leading SCONE packet and shift the QUIC packet up.
int remove_scone_ebpf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    size_t lower_hdrlen = sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr);
    u64 result = check_quic(data, data_end);

    if (result != SCONE_COUNTER) {
        counters.increment(result);
        return XDP_PASS;
    }

    // Copy the lower headers back, overwriting the SCONE packet.
    __builtin_memmove(data+sizeof(struct sconepkt), data, lower_hdrlen);
    // Adjust the packet length to shrink it.
    if (bpf_xdp_adjust_head(ctx, -(sizeof(struct sconepkt))) != 0) {
        // TODO: Some kind of error.
        return XDP_PASS;
    }

    result = SCONE_REMOVED_COUNTER;
    counters.increment(result);

    return XDP_PASS;
}
