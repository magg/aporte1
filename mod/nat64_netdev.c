#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/route.h>
#include <linux/skbuff.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>

#include "xt_nat64.h"

#define NAT64_NETDEV_NAME "nat64"

static int nat64_netdev_up(struct net_device *dev);
static int nat64_netdev_down(struct net_device *dev);
static netdev_tx_t nat64_netdev_xmit(struct sk_buff *skb, struct net_device *dev);

static const struct net_device_ops nat64_netdev_ops = {
//	.ndo_init	= ,	// Called at register_netdev
//	.ndo_uninit	= ,	// Called at unregister_netdev
	.ndo_open	= nat64_netdev_up,	// Called at ifconfig nat64 up
	.ndo_stop	= nat64_netdev_down,	// Called at ifconfig nat64 down
	.ndo_start_xmit	= nat64_netdev_xmit,	// REQUIRED, must return NETDEV_TX_OK
//	.ndo_change_rx_flags = ,	// Called when setting promisc or multicast flags.
//	.ndo_change_mtu = ,
//	.net_device_stats = ,	// Called for usage statictics, if NULL dev->stats will be used.
};

static int nat64_netdev_up(struct net_device *dev)
{
	/*struct fib6_config cfg = {
		.fc_table = RT6_TABLE_MAIN,
		.fc_metric = IP6_RT_PRIO_ADDRCONF,
		.fc_ifindex = dev->ifindex,
		.fc_expires = 0,
		.fc_dst_len = prefix_len,
		.fc_flags = RTF_UP | RTF_NONEXTHOP,
		.fc_nlinfo.nl_net = dev_net(dev),
		.fc_protocol = RTPROT_KERNEL,
	};*/

	netif_start_queue(dev);
	/*printk("nat64: the device is going up, you shoud automagically add nat64 prefix route :).\n");
	
	ipv6_addr_copy(&cfg.fc_dst, &prefix_base);
	ip6_route_add(&cfg);*/
	return 0;
}

static int nat64_netdev_down(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t nat64_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	switch(ntohs(skb->protocol)) {
	case ETH_P_IP:
		nat64_tg4(skb);
		break;
	case ETH_P_IPV6:
		nat64_tg6(skb);
		break;
	}

	kfree_skb(skb);
	return NETDEV_TX_OK;
}

/*static void *nat64_netdev_free(struct net_device *dev)
{
	// Free private data???
} */

static void nat64_netdev_setup(struct net_device *dev)
{
//      struct nat64_netdev_private *nat64 = netdev_priv(dev);

	dev->netdev_ops = &nat64_netdev_ops;
//	dev->destructor = nat64_netdev_free;

	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = ETH_DATA_LEN;
	dev->features = NETIF_F_NETNS_LOCAL | NETIF_F_NO_CSUM;
	dev->flags = IFF_NOARP | IFF_POINTOPOINT;
}

int nat64_netdev_create(struct net_device **dev)
{
	int ret = 0;
	//dev = alloc_netdev(sizeof(struct nat64_netdev_priv), NAT64_NETDEV_NAME, nat64_netdev_setup);
	*dev = alloc_netdev(0, NAT64_NETDEV_NAME, nat64_netdev_setup);

	if (!*dev) {
		printk("nat64: Unable to allocate nat64 device. Not enough memory X(.\n");
		return -ENOMEM;
	}

	ret = register_netdev(*dev);
	if(ret) {
		printk("nat64: Unable to register nat64 device X(.\n");
		free_netdev(*dev);
		return ret;
	}

	printk("nat64: netdevice created successfully.\n");
	return ret;
}

void nat64_netdev_destroy(struct net_device *dev)
{
	unregister_netdev(dev);

	printk("NAT64: Destroying nat64 device.\n");
}

