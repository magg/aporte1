#ifndef _XT_NAT64_H
#define _XT_NAT64_H

/*
 * Flags that indicate the information needed for the NAT64 device.
 */
enum
{
	XT_NAT64_IP_SRC = 1 << 0, //
	XT_NAT64_IP_DST = 1 << 1, //
	XT_NAT64_IPV6_DST = 1 << 2, //
	XT_NAT64_OUT_DEV = 1 << 3,
};

struct xt_nat64_tginfo
{
	union nf_inet_addr ipdst, ipdst_mask;
	union nf_inet_addr ipsrc, ipsrc_mask;
	union nf_inet_addr ip6dst, ip6dst_mask;
	__u16 l4proto;
	char out_dev[IFNAMSIZ];
	char out_dev_mask[IFNAMSIZ];
	__u8 flags;
};

int nat64_netdev_create(struct net_device **dev);
void nat64_netdev_destroy(struct net_device *dev);
unsigned int nat64_tg4(struct sk_buff *skb);
unsigned int nat64_tg6(struct sk_buff *skb);

/**
 * Transport layer protocols allowed by the NAT64 implementation when the
 * network protocol is IPv4.
 */
#define NAT64_IP_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMP)
/**
 * Transport layer protocols allowed by the NAT64 implementation when the
 * network protocol is IPv6.
 */
#define NAT64_IPV6_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMPV6)


#endif /* _XT_NAT64_H */
