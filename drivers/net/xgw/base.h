
#include <linux/init.h>
#include <linux/kernel.h>
#ifdef CONFIG_HIGH_RES_TIMERS
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#endif
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

#define __prefetch_r_temporal_none(addr)     __builtin_prefetch((addr), 0, 0)
#define __prefetch_w_temporal_none(addr)     __builtin_prefetch((addr), 1, 0)
#define __prefetch_s_temporal_none(addr)     __builtin_prefetch((addr), 2, 0)
#define __prefetch_r_temporal_low(addr)      __builtin_prefetch((addr), 0, 1)
#define __prefetch_w_temporal_low(addr)      __builtin_prefetch((addr), 1, 1)
#define __prefetch_s_temporal_low(addr)      __builtin_prefetch((addr), 2, 1)
#define __prefetch_r_temporal_moderate(addr) __builtin_prefetch((addr), 0, 2)
#define __prefetch_w_temporal_moderate(addr) __builtin_prefetch((addr), 1, 2)
#define __prefetch_s_temporal_moderate(addr) __builtin_prefetch((addr), 2, 2)
#define __prefetch_r_temporal_high(addr)     __builtin_prefetch((addr), 0, 3)
#define __prefetch_w_temporal_high(addr)     __builtin_prefetch((addr), 1, 3)
#define __prefetch_s_temporal_high(addr)     __builtin_prefetch((addr), 2, 3)

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
#define BE16 __builtin_bswap16
#define BE32 __builtin_bswap32
#define BE64 __builtin_bswap64
#endif

#define ABS_DIFF(a, b) ({ \
    const typeof(a) _a = a; \
    const typeof(b) _b = b; \
    _a >= _b ?    \
        _a - _b : \
        _b - _a ; \
})

#define atomic_get(ptr)      __atomic_load_n (ptr,    __ATOMIC_RELAXED)
#define atomic_set(ptr, v)   __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
