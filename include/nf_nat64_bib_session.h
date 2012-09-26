#ifndef _NF_NAT64_BIB_SESSION_H
#define _NF_NAT64_BIB_SESSION_H

#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include "nf_nat64_ipv4_pool.h"

// #define UDP_MIN_ (2 * 60) // Still unused.
#define UDP_DEFAULT_ (5 * 60)
#define TCP_TRANS_ (4 * 60)
#define TCP_EST_ (2 * 60 * 60)
#define TCP_INCOMING_SYN_ (6)
// #define FRAGMENT_MIN_ (2) // Still unused.
#define ICMP_DEFAULT_ (1 * 60)

//#define BIB_ICMP 3
#define	NUM_EXPIRY_QUEUES 5

enum expiry_type
{
	UDP_DEFAULT = 0, //
	TCP_TRANS, //
	TCP_EST, //
	TCP_INCOMING_SYN, //
	ICMP_DEFAULT
};

enum state_type
{
	CLOSED = 0,
	V6_SYN_RCV,
	V4_SYN_RCV,
	FOUR_MIN,
	ESTABLISHED,
	V6_FIN_RCV,
	V4_FIN_RCV,
	V6_FIN_V4_FIN,
};

struct expiry_q
{
	struct list_head queue;
	int timeout;
};

struct nat64_bib_entry
{
	struct hlist_node byremote;
	struct hlist_node bylocal;

	int type;
	struct in6_addr remote6_addr; // X' addr
	__be32 local4_addr; // T' addr

	__be16 remote6_port; // x port
	__be16 local4_port; // t port

	struct list_head sessions;
};

struct nat64_st_entry
{
	struct list_head list;
	struct list_head byexpiry;
	struct in6_addr remote6_addr; // X' addr
	struct in6_addr embedded6_addr; // Y' addr
	unsigned long expires;
	int state;
	__be32 local4_addr; // T' addr
	__be32 remote4_addr; // Z' addr
	__be16 remote6_port; // x port
	__be16 embedded6_port; // y port
	__be16 remote4_port; // z port
	__be16 local4_port; // t port
};

int nat64_create_bib_session_memory(void);
int nat64_destroy_bib_session_memory(void);

int nat64_tcp_timeout_fsm(struct nat64_st_entry *session);
void nat64_tcp4_fsm(struct nat64_st_entry *session, struct tcphdr *tcph);
void nat64_tcp6_fsm(struct nat64_st_entry *session, struct tcphdr *tcph);

struct nat64_bib_entry *nat64_bib_ipv6_lookup(struct in6_addr *remote_addr,
        __be16 remote_port, int type);
struct nat64_bib_entry *nat64_bib_ipv4_lookup(__be32 local_addr,
        __be16 local_port, int type);
struct nat64_bib_entry *nat64_bib_create(struct in6_addr *remote6_addr,
        __be16 remote6_port, __be32 local4_addr, __be16 local4_port, int type);
struct nat64_bib_entry *nat64_bib_create_tcp(struct in6_addr *remote6_addr,
        __be16 remote6_port, __be32 local4_addr, __be16 local4_port, int type);
struct nat64_bib_entry *nat64_bib_session_create_tcp(struct in6_addr *saddr,
        struct in6_addr *in6_daddr, __be32 daddr, __be16 sport, __be16 dport,
        int protocol, enum expiry_type type);
struct nat64_bib_entry *nat64_bib_session_create_icmp(struct in6_addr *saddr,
        struct in6_addr *in6_daddr, __be32 daddr, __be16 sport, __be16 dport,
        int protocol, enum expiry_type type);
struct nat64_bib_entry *nat64_bib_session_create(struct in6_addr *saddr,
        struct in6_addr *in6_daddr, __be32 daddr, __be16 sport, __be16 dport,
        int protocol, enum expiry_type type);

struct nat64_st_entry *nat64_session_ipv4_lookup(struct nat64_bib_entry *bib,
        __be32 saddr, __be16 sport);
struct nat64_st_entry *nat64_session_create(struct nat64_bib_entry *bib,
        struct in6_addr *in6_daddr, __be32 addr, __be16 port,
        enum expiry_type type);
struct nat64_st_entry *nat64_session_create_tcp(struct nat64_bib_entry *bib,
        struct in6_addr *in6_daddr, __be32 addr, __be16 port,
        enum expiry_type type);
struct nat64_st_entry *nat64_session_create_icmp(struct nat64_bib_entry *bib,
        struct in6_addr *in6_daddr, __be32 addr, __be16 port,
        enum expiry_type type);

void nat64_session_renew(struct nat64_st_entry *session, enum expiry_type type);

int nat64_allocate_hash(unsigned int size);
void nat64_clean_expired_sessions(struct list_head *queue, int j);
struct nat64_st_entry *nat64_session_ipv4_hairpin_lookup(
        struct nat64_bib_entry *bib, __be32 local4_addr, __be16 local4_port);

#endif /* _NF_NAT64_BIB_SESSION_H */
