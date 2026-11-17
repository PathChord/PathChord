#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <stddef.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define bpf_htons(value) __builtin_bswap16(value)

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)(unsigned long)BPF_FUNC_map_lookup_elem;
static int (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset,
					 void *to, __u32 len) =
	(void *)(unsigned long)BPF_FUNC_skb_load_bytes;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} pathchord_config_map SEC(".maps");

static __always_inline int mark_transport(struct __sk_buff *skb, __u32 mark)
{
	__u16 protocol = 0;
	__u8 transport = 0;

	if (skb->mark != 0 ||
	    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &protocol,
					       sizeof(protocol)) < 0)
		return TC_ACT_OK;
	if (protocol == bpf_htons(ETH_P_IP)) {
		if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
					       &transport, sizeof(transport)) < 0)
			return TC_ACT_OK;
	} else if (protocol == bpf_htons(ETH_P_IPV6)) {
		if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr),
					       &transport, sizeof(transport)) < 0)
			return TC_ACT_OK;
		/* IPv6 fragments keep the transport protocol in their next-header byte.
		 * Mark every fragment consistently so kernel reassembly and TPROXY see
		 * the same policy-routing mark for large UDP datagrams. */
		if (transport == IPPROTO_FRAGMENT &&
		    bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct ipv6hdr),
				       &transport, sizeof(transport)) < 0)
			return TC_ACT_OK;
	} else {
		return TC_ACT_OK;
	}
	if (transport != IPPROTO_TCP && transport != IPPROTO_UDP)
		return TC_ACT_OK;
	skb->mark = mark;
	return TC_ACT_OK;
}

SEC("classifier")
int pathchord_tproxy(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u32 *mark = bpf_map_lookup_elem(&pathchord_config_map, &key);

	if (!mark || *mark == 0)
		return TC_ACT_OK;
	return mark_transport(skb, *mark);
}

char LICENSE[] SEC("license") = "GPL";
