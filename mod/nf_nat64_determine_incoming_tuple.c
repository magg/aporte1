#include <net/ip.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include "nf_nat64_determine_incoming_tuple.h"

/** The IPv4 protocol. */
//struct nf_conntrack_l3proto * l3proto_ip __read_mostly;
/** The IPv6 protocol. */
//struct nf_conntrack_l3proto * l3proto_ipv6 __read_mostly;

/*
 * Function that receives a tuple and prints it.
 */
void nat64_print_tuple(const struct nf_conntrack_tuple *t)
{
	pr_debug("NAT64: print_tuple -> l3 proto = %d", t->src.l3num);
	switch(t->src.l3num) {
		case NFPROTO_IPV4:
			pr_debug("NAT64: tuple %p: %u %pI4:%hu -> %pI4:%hu",
					t, t->dst.protonum,
					&t->src.u3.ip, ntohs(t->src.u.all),
					&t->dst.u3.ip, ntohs(t->dst.u.all));
			break;
		case NFPROTO_IPV6:
			pr_debug("NAT64: tuple %p: %u %pI6c: %hu -> %pI6c:%hu",
					t, t->dst.protonum,
					&t->src.u3.all, ntohs(t->src.u.all),
					&t->dst.u3.all, ntohs(t->dst.u.all) );
			break;
		default:
			pr_debug("NAT64: Not IPv4 or IPv6?");
	}
}

/*
 * Returns the Layer 3 header length.
 */
int nat64_get_l3hdrlen(struct sk_buff *skb, u_int8_t l3protocol)
{
	switch (l3protocol) {
		case NFPROTO_IPV4:
			pr_debug("NAT64 get_l3hdrlen is IPV4");
			return ip_hdrlen(skb);
		case NFPROTO_IPV6:
			pr_debug("NAT64 get_l3hdrlen is IPV6");
			return (skb_network_offset(skb) + sizeof(struct ipv6hdr));
		default:
			return -1;
	}
}

/*
 * Function that gets the pointer directed to its
 * nf_conntrack_l3proto structure.
 
int nat64_get_l3struct(u_int8_t l3protocol,
		struct nf_conntrack_l3proto ** l3proto)
{
	switch (l3protocol) {
		case NFPROTO_IPV4:
			*l3proto = l3proto_ip;
			return true;
		case NFPROTO_IPV6:
			*l3proto = l3proto_ipv6;
			return true;
		default:
			return false;
	}
}
*/
/*
 * Function to get the tuple out of a given struct sk_buff.
 
bool nat64_get_tuple(u_int8_t l3protocol, u_int8_t l4protocol,
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
	const struct nf_conntrack_l4proto *l4proto;
	struct nf_conntrack_l3proto *l3proto;
	int l3_hdrlen, ret;
	unsigned int protoff = 0;
	u_int8_t protonum = 0;

	pr_debug("NAT64: Getting the protocol and header length");

	
	l3_hdrlen = nat64_get_l3hdrlen(skb, l3protocol);

	if (l3_hdrlen == -1) {
		pr_debug("NAT64: Something went wrong getting the"
				" l3 header length");
		return false;
	}

	
	if (!(nat64_get_l3struct(l3protocol, &l3proto)))
		return false;

	if (l3proto == NULL) {
		pr_info("NAT64: nat64_get_tuple - the l3proto pointer is null");
		return false;
	}

	rcu_read_lock();

	pr_debug("NAT64: l3_hdrlen = %d", l3_hdrlen);

	
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb),
			&protoff, &protonum);

	if (ret != NF_ACCEPT) {
		pr_info("NAT64: nat64_get_tuple - error getting the L4 offset");
		pr_debug("NAT64: ret = %d", ret);
		pr_debug("NAT64: protoff = %u", protoff);
		rcu_read_unlock();
		return false;
	} else if (protonum != l4protocol) {
		pr_info("NAT64: nat64_get_tuple - protocols don't match");
		pr_debug("NAT64: protonum = %u", protonum);
		pr_debug("NAT64: l4protocol = %u", l4protocol);
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3protocol, l4protocol);
	pr_debug("l4proto name = %s %d %d", l4proto->name,
			(u_int32_t)l4proto->l3proto, (u_int32_t)l4proto->l4proto);

	
	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
				l3_hdrlen,
				(u_int16_t)l3protocol, l4protocol,
				inner, l3proto, l4proto)) {
		pr_debug("NAT64: couldn't get the tuple");
		rcu_read_unlock();
		return false;
	}

	pr_debug("\nPRINTED TUPLE");
	nat64_print_tuple(inner);
	pr_debug("\n");
	rcu_read_unlock();

	return true;
}

bool nat64_determine_incoming_tuple_init(void)
{
	l3proto_ip = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV4);
	if (l3proto_ip == NULL) {
		pr_warning("NAT64: couldn't load IPv4 l3proto");
		return false;
	} 

	l3proto_ipv6 = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV6);
	if (l3proto_ipv6 == NULL) {
		pr_warning("NAT64: couldn't load IPv6 l3proto");
		return false;
	}

	return true;
}


 * Function that gets the packet's information and returns a tuple out of it.
 */
bool nat64_determine_incoming_tuple(u_int8_t l3protocol, u_int8_t l4protocol,
		struct sk_buff *skb, struct nf_conntrack_tuple * inner)
{
struct udphdr *uh;
struct tcphdr *th;
struct icmphdr * icmph;
struct icmp6hdr * icmph6;
struct iphdr *iph;
struct ipv6hdr * ip6;


		inner->src.l3num = (u_int16_t)l3protocol;
		inner->dst.protonum = (u_int8_t)l4protocol;
		switch(l3protocol){
			case NFPROTO_IPV4:
					iph = ip_hdr(skb);

					switch(l4protocol){
						case IPPROTO_UDP:
						  uh = (struct udphdr *) (skb->data + (iph->ihl*4));
						  inner->src.u.udp.port = uh->source; // y port
			       			  inner->dst.u.udp.port = uh->dest; // x port
						break;
						case IPPROTO_TCP:
 						  th = (struct tcphdr *) (skb->data + (iph->ihl*4));
						  inner->src.u.tcp.port = th->source; // y port
			       			  inner->dst.u.tcp.port = th->dest; // x port
						break;
						case IPPROTO_ICMP:
							icmph = (struct icmphdr *) (skb->data + (iph->ihl*4));;
							inner->src.u.icmp.id = 	icmph->un.echo.id;
							inner->dst.u.icmp.type = icmph->type;
							inner->dst.u.icmp.type = icmph->code; 
						break;
					}
				inner->src.u3.in.s_addr = iph->saddr;
				inner->dst.u3.in.s_addr = iph->daddr;
					
			break;
			case NFPROTO_IPV6:
				ip6 = ipv6_hdr(skb);
				switch(l4protocol){
					case IPPROTO_UDP:
						  uh = udp_hdr(skb);
						  inner->src.u.udp.port = uh->source; // y port
			       			  inner->dst.u.udp.port = uh->dest; // x port
					break;
					case IPPROTO_TCP:
  						  th = tcp_hdr(skb);
						  inner->src.u.tcp.port = th->source; // y port
			       			  inner->dst.u.tcp.port = th->dest; // x port
					break;
					case IPPROTO_ICMPV6:
							icmph6 = icmp6_hdr(skb);
							inner->src.u.icmp.id = 	icmph6->icmp6_dataun.u_echo.identifier;
							inner->dst.u.icmp.type = icmph6->icmp6_type;
							inner->dst.u.icmp.type = icmph6->icmp6_code;  
					break;
				}
				                // SRC IP
               			ipv6_addr_copy(&inner->src.u3.in6,&ip6->saddr); // Y' addr
                		ipv6_addr_copy(&inner->dst.u3.in6,&ip6->daddr); // X' addr

			break;
		}

              

nat64_print_tuple(inner);




    pr_debug("NAT64: Determining the tuple stage went OK.");

    return true;
}
/*

void nat64_determine_incoming_tuple_destroy(void)
{
	nf_ct_l3proto_put(l3proto_ip);
	nf_ct_l3proto_put(l3proto_ipv6);
}

*/

