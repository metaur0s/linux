
#ifndef __XGW_BASE__
#define __XGW_BASE__

#include "kconfig.h"

#if 1
#define BUILD_ASSERT(c) _Static_assert((c), #c)
#else
#define BUILD_ASSERT(c)
#endif

#ifdef CONFIG_XGW_ASSERT
#define ASSERT(c) ({ if (unlikely(!(c))) printk("XGW: %s:%d: ASSERT FAILED: %s\n", __FILE__, __LINE__, #c); })
#else
#define ASSERT(c) __attribute__((assume(c)))
#endif

#define CACHE_LINE_SIZE 64

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <linux/proc_fs.h>
#ifdef CONFIG_XGW_BEEP
#include <linux/i8253.h>
#endif

#define ___JOIN(a, b) a ## b
#define SUFFIX_ULL(l) ___JOIN(l, ULL)
#define SUFFIX_U(l)   ___JOIN(l, U)

#define __noinline __attribute__((noinline))
#define __cold_as_ice __attribute__((cold))

#if defined(__clang__)
#define __optimize_size
#elif defined(__GNUC__)
#define __optimize_size __attribute__((optimize("Os")))
#endif

#define ETH_SIZE 14 // ETH_HLEN
#define IP4_SIZE 20 // sizeof(struct iphdr)
#define IP6_SIZE 40 // sizeof(struct ipv6hdr)
#define TCP_SIZE 20 // sizeof(struct tcphdr)
#define UDP_SIZE  8 // sizeof(struct udphdr)

// TODO:
#define popcount32 __builtin_popcount
#define popcount64 __builtin_popcountll

#define popcount(x) \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x),  int  ), __builtin_popcount(x),   \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x), uint  ), __builtin_popcount(x),   \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x),  intll), __builtin_popcountll(x), \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x), uintll), __builtin_popcountll(x), \
    __builtin_choose_expr(                    sizeof(x) <= sizeof(uint),   __builtin_popcount(x),   \
                                                                           __builtin_popcountll(x))))))

#define __ctz(x) \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x),  int  ), __builtin_ctz(x),   \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x), uint  ), __builtin_ctz(x),   \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x),  intll), __builtin_ctzll(x), \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(x), uintll), __builtin_ctzll(x), \
    __builtin_choose_expr(                    sizeof(x) <= sizeof(uint),   __builtin_ctz(x),   \
                                                                           __builtin_ctzll(x))))))

typedef __u8   u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef __s64 s64;

typedef          long long int intll;
typedef unsigned long long int uintll;

typedef atomic_t atomic32_t;

typedef struct sk_buff        skb_s;
typedef struct net_device     net_device_s;
typedef struct net            net_s;
typedef struct header_ops     header_ops_s;
typedef struct net_device_ops net_device_ops_s;

#define SKB_USERS(skb) refcount_read(&(skb)->users)

#define SKB_HEAD(skb)      PTR((skb)->head)
#define SKB_DATA(skb)      PTR((skb)->data)
#define SKB_TAIL(skb)      PTR(skb_tail_pointer(skb))
#define SKB_END(skb)       PTR(skb_end_pointer(skb))
#define SKB_MAC(skb)       PTR(skb_mac_header(skb))
#define SKB_NETWORK(skb)   PTR(skb_network_header(skb))
#define SKB_TRANSPORT(skb) PTR(skb_transport_header(skb))

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif else if

#define for_count(i, count) for (typeof(count) i = 0, __q = (count); i != __q; i++)

#define BE8(x)  (x)
#ifdef __BIG_ENDIAN
#define BE16(x) (x)
#define BE32(x) (x)
#define BE64(x) (x)
#else
#define BE16(x) ((u16)__builtin_bswap16((u16)(x)))
#define BE32(x) ((u32)__builtin_bswap32((u32)(x)))
#define BE64(x) ((u64)__builtin_bswap64((u64)(x)))
#endif

// ALIGNDING FOR CACHE-LINE SIZE
#define ALIGN_NEED(x) ((x) % CACHE_LINE_SIZE)
#define ALIGN_MAKE(x) char _ [CACHE_LINE_SIZE - ((x) % CACHE_LINE_SIZE)];
#define ALIGN_SIZE(x) ((x) + (!!ALIGN_NEED(x)) * (CACHE_LINE_SIZE - ((x) % CACHE_LINE_SIZE)) )

#define ABS_DIFF(a, b) ({ \
    const typeof(a) _a = a; \
    const typeof(b) _b = b; \
    _a >= _b ?    \
        _a - _b : \
        _b - _a ; \
})

#define atomic_get(ptr)      __atomic_load_n   (ptr,    __ATOMIC_RELAXED)
#define atomic_set(ptr, v)   __atomic_store_n  (ptr, v, __ATOMIC_RELAXED)
#define atomic_add(ptr, v)   __atomic_add_fetch(ptr, v, __ATOMIC_RELAXED)
#define atomic_sub(ptr, v)   __atomic_sub_fetch(ptr, v, __ATOMIC_RELAXED)
#define atomic_inc(ptr)      __atomic_add_fetch(ptr, 1, __ATOMIC_RELAXED)

#define acquire_get(ptr)      __atomic_load_n   (ptr,    __ATOMIC_ACQUIRE)
#define acquire_add(ptr, v)   __atomic_add_fetch(ptr, v, __ATOMIC_ACQUIRE)
#define acquire_sub(ptr, v)   __atomic_sub_fetch(ptr, v, __ATOMIC_ACQUIRE)
#define acquire_inc(ptr)      __atomic_add_fetch(ptr, 1, __ATOMIC_ACQUIRE)

#define release_set(ptr, v)   __atomic_store_n  (ptr, v, __ATOMIC_RELEASE)
#define release_add(ptr, v)   __atomic_add_fetch(ptr, v, __ATOMIC_RELEASE)
#define release_sub(ptr, v)   __atomic_sub_fetch(ptr, v, __ATOMIC_RELEASE)
#define release_inc(ptr)      __atomic_add_fetch(ptr, 1, __ATOMIC_RELEASE)

#define atomic_from_to(ptr, old, new)  __atomic_compare_exchange_n(ptr, old, new, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)
#define acquire_from_to(ptr, old, new) __atomic_compare_exchange_n(ptr, old, new, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)

typedef u64 u64x8 __attribute__ ((vector_size(8 * sizeof(u64))));

typedef struct pkt_s  pkt_s;
typedef struct path_s path_s;
typedef struct node_s node_s;
typedef struct stat_s stat_s;

typedef union cmd_arg_s cmd_arg_s;

typedef struct ip4_s ip4_s;
typedef struct ip6_s ip6_s;

typedef struct hdr_ip4_s   hdr_ip4_s;
typedef struct hdr_ip6_s   hdr_ip6_s;
typedef struct hdr_udp_s   hdr_udp_s;
typedef struct hdr_tcp_s   hdr_tcp_s;
typedef struct hdr_eth_s   hdr_eth_s;
typedef struct hdr_vlan_s  hdr_vlan_s;
typedef struct hdr_ppp_s   hdr_ppp_s;

typedef struct encap_eth_s              encap_eth_s;
typedef struct encap_eth_ip4_s          encap_eth_ip4_s;
typedef struct encap_eth_ip6_s          encap_eth_ip6_s;
typedef struct encap_eth_ip4_udp_s      encap_eth_ip4_udp_s;
typedef struct encap_eth_ip6_udp_s      encap_eth_ip6_udp_s;
typedef struct encap_eth_vlan_s         encap_eth_vlan_s;
typedef struct encap_eth_vlan_ip4_s     encap_eth_vlan_ip4_s;
typedef struct encap_eth_vlan_ip6_s     encap_eth_vlan_ip6_s;
typedef struct encap_eth_vlan_ip4_udp_s encap_eth_vlan_ip4_udp_s;
typedef struct encap_eth_vlan_ip6_udp_s encap_eth_vlan_ip6_udp_s;
typedef struct encap_ip4_s              encap_ip4_s;
typedef struct encap_ip6_s              encap_ip6_s;
typedef struct encap_ip4_udp_s          encap_ip4_udp_s;
typedef struct encap_ip4_tcp_s          encap_ip4_tcp_s;
typedef struct encap_ip6_udp_s          encap_ip6_udp_s;
typedef struct encap_ip6_tcp_s          encap_ip6_tcp_s;

typedef struct encap_eth_ppp_s          encap_eth_ppp_s;
typedef struct encap_eth_ppp_ip4_s      encap_eth_ppp_ip4_s;
typedef struct encap_eth_ppp_ip6_s      encap_eth_ppp_ip6_s;
typedef struct encap_eth_vlan_ppp_s     encap_eth_vlan_ppp_s;
typedef struct encap_eth_vlan_ppp_ip4_s encap_eth_vlan_ppp_ip4_s;
typedef struct encap_eth_vlan_ppp_ip6_s encap_eth_vlan_ppp_ip6_s;

typedef struct hdr_x_s hdr_x_s;

//
static inline u64   swap64 (const u64 x) { const uint q = popcount64(x); return (x >> q) | (x << (64 - q)); }
static inline u64 unswap64 (const u64 x) { const uint q = popcount64(x); return (x << q) | (x >> (64 - q)); }

static inline u64 __u64x8_sum_reduced (const u64x8 V[], const uint n) {

    u64x8 v = { 0, 0, 0, 0, 0, 0, 0, 0 };

    for (uint i = 0; i != n; i++)
        v += V[i];

    return v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
}

#endif
