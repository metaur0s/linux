/*

*/


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

// ALL UDP PORTS
#define UDP_PORTS_N 65536

//
#define PORTS_N (UDP_PORTS_N / PORTS_WIDTH)

#define PORTS_WIDTH 32
#define PORTS_SHIFT 5
#define PORTS_MASK 0b11111
#define PORTS_W (ports[port >> PORTS_SHIFT])
#define PORTS_B (1 << (port & PORTS_MASK))

typedef int ports_t;

#ifdef CONFIG_XGW_GATEWAY
#define XGW_TCP_PROXY_MARK_4 0x25440000U
#define XGW_TCP_PROXY_MARK_6 0x25660000U
#endif

// QUANTO MAIS INTERVALOS AGUENTA MAIS TEMPO DE FALHAS DE CONEXAO SEM TER QUE RENEGOCIAR E EXPOR AS PRESHAREDS
// QUANTO MAIS INTERVALOS MENOS PROBABILIDADE DA RESINCRONIZACAO DE L/R COUNTERS SOBRESCREVER IKEYS ATUAIS

//
#define MTU_MIN XGW_PAYLOAD_MIN
#define MTU_MAX XGW_PAYLOAD_MAX

#define GWS_N 8

// A XGW ADDRESS IS COMPOSED OF
// PREFIX | NODE | SUB

// 192.0.0.0/24
#define V4_PREFIX 0xC0000000U
#define V4_WIDTH_PREFIX 24
#define V4_WIDTH_NODE 8

// fccc::/16         -> XGW'S NETWORK
// fccc:NODE::/32    -> NODE'S NETWORK
#define V6_PREFIX 0xFCCC000000000000ULL
#define V6_WIDTH_PREFIX 16
#define V6_WIDTH_NODE 16

//
#define KEYS_N 8

#define K_LEN 8

#define SECRET_PAIRS_N 1024

#define SECRET_SIZE 65536

// DO QUAL DERIVAREMOS O SECRET
#define PASSWORD_SIZE_MIN    16
#define PASSWORD_SIZE_MAX 65536

//
#define PASSWORD_ROUNDS 16


//
#define CONNS_MIN CONFIG_XGW_CONNS_MIN
#define CONNS_MAX CONFIG_XGW_CONNS_MAX

//
#define CONNS_SIZE(connsN) ((connsN) * sizeof(u64))

//
#define NODE_NAME_SIZE 32
#define PATH_NAME_SIZE 20 // "super-ISP-1-ip6-udp\0"

//
#define NODES_N 65536

// MANY PATHS ARE GOOD FOR:
//  - TRAFFIC SHAPING
//  - TRAFFIC RATING (ISP WON'T SEE A SINGLE CONNECTION WITH TOO MANY SPEED/CUMULATIVE USAGE)
//  - MORE SECURITY (MORE CODES USED) --- NOT ANYMORE
//  - MORE SECURITY (MORE KEYS GENERATED)
//  - MORE SECURITY (MORE KEYS GENERATED THUS EXPIRATION IS FASTER)
//  - RESILIENCY AGAINST BROKEN PATHS
//  - NIC HASHING
//  - RECEIVE CAN BE DISTRIBUTED TO MORE CPUS
#define PATHS_N 16

//
#define NID_MAX (NODES_N - 1)
#define PID_MAX (PATHS_N - 1)

//
#define PATH_PORTS_N 4

// TODO: ASSERT( (typeof(path->weight))PATH_WEIGHT_MAX == PATH_WEIGHT_MAX )
// TODO: ASSERT( (typeof(node->weights))(PATH_WEIGHT_MAX * PATHS_N) == (PATH_WEIGHT_MAX * PATHS_N) )
#define PATH_WEIGHT_MAX 255

// HOW MANY ACKS IN HISTORY
// (WORD LENGTH)
#define ACKS_N 64

// NODE INFO
#define N_ON      (1U << 0)
#define N_NAME    (1U << 1)
#define N_MTU     (1U << 2)
#define N_CONNS_N (1U << 3)
#define N_SECRET  (1U << 4)
#define N_INFO   ((1U << 5) - 1)

// PATH STATUS/INFO
#define P_ON                  (1U <<  0)
#define P_CLIENT              (1U <<  1)
#define P_SERVER              (1U <<  2)
#define P_PHYS                (1U <<  3)
#define P_MAC_SRC             (1U <<  4)
#define P_MAC_DST             (1U <<  5)
#define P_ADDR_SRC            (1U <<  6)
#define P_ADDR_DST            (1U <<  7)
#define P_PORT_SRC            (1U <<  8)
#define P_PORT_DST            (1U <<  9)
#define P_TOS                 (1U << 10)
#define P_TTL                 (1U << 11)
#define P_VPROTO              (1U << 12)
#define P_VID                 (1U << 13)
#define P_RTT_MIN             (1U << 14)
#define P_RTT_MAX             (1U << 15)
#define P_RTT_VAR             (1U << 16)
#define P_TIMEOUT             (1U << 17)
#define P_NAME                (1U << 18)
#define P_DHCP                (1U << 19)
#define P_DHCP_MAC_DST_SERVER (1U << 20)
#define P_DHCP_MAC_DST_GW     (1U << 21)
#define P_EXIST               (1U << 22)
// TODO: P_INFO_WEIGHT_NODE
// TODO: P_INFO_WEIGHT_ACKS
#define P_INFO               ((1U << 23) - 1)
#define K_START               (1U << 23)
#define K_SUSPEND             (1U << 24)
#define K_SUSPENDING          (1U << 25)
#define K_LISTEN              (1U << 26) // TODO: RENAME TO K_DISCOVERING
#define K_ESTABLISHED         (1U << 27) // TODO: RENAME TO K_PINGING
#define P_ALL                ((1U << 28) - 1)

// P_VPROTO -> NOTE: IT IS THE ETH->PROTO, NOT THE VLAN->PROTO

// INFORMACOES QUE SAO PERDIDAS AO MUDAR O TIPO DE ENCAPSULAMENTO
// TODO: P_DHCP ?
#define __P_TYPE_CLR (P_MAC_SRC | P_MAC_DST | P_ADDR_SRC | P_ADDR_DST | P_VPROTO | P_VID | P_DHCP)

//
#define PATH_RTTS_N 16

// 10ms - 625ms
#define PATH_RTT_MIN (HZ / 100)
#define PATH_RTT_MAX ((25 * HZ) / 40)

// 10ms - 120ms
#define PATH_RTT_VAR_MIN (HZ / 100)
#define PATH_RTT_VAR_MAX ((3 * HZ) / 25)

// 15ms - 750ms
#define PATH_RTT_EFFECTIVE_MIN (HZ / 64)
#define PATH_RTT_EFFECTIVE_MAX ((75 * HZ) / 100)

// NOTE: NAO ADIANTA SER MUITO LONGO POIS OS KEYS PODEM ACABAR SENDO INUTILIZADOS
// NOTE: NAO ADIANTA SER LONGO POIS FICARA UM TEMPAO TRAVADO (SERVER)
// NOTE: NAO ADIANTA SER LONGO POIS FICARA UM TEMPAO TRAVADO (CLIENT)
#define PATH_TIMEOUT_MIN   1
#define PATH_TIMEOUT_MAX 255

//
BUILD_ASSERT(PATH_RTT_MIN     >= 1);
BUILD_ASSERT(PATH_RTT_VAR_MIN >= 1);

BUILD_ASSERT(PATH_RTT_MIN     < PATH_RTT_MAX);
BUILD_ASSERT(PATH_RTT_VAR_MIN < PATH_RTT_VAR_MAX);
BUILD_ASSERT(PATH_TIMEOUT_MIN < PATH_TIMEOUT_MAX);

//
BUILD_ASSERT((PATH_RTT_MIN + PATH_RTT_VAR_MIN) >= PATH_RTT_EFFECTIVE_MIN);
BUILD_ASSERT((PATH_RTT_MAX + PATH_RTT_VAR_MAX) <= PATH_RTT_EFFECTIVE_MAX);

// TEM QUE TER UMA FOLGUINHA...
BUILD_ASSERT(PATH_RTT_EFFECTIVE_MAX < ((85 * KEEPER_INTERVAL) / 100));

//
#define PATH_SIZE 320

struct path_s {
// 64 -- KEEPER / IN
  // 16 RO
    u32 info;
    u16 nid;
    u8  pid;
    u8  timeout; // CONFIG | O CMD VAI CONVERTER O TEMPO EM SEGUNDOS/MINUTOS EM HIFFIES
    u8  weight;
    u8  weight_acks;
    u16 rtt_min; // CONFIG
    u16 rtt_max; // CONFIG
    u16 rtt_var; // CONFIG
// --
    u64 lcounter; // IN_PONG | MEU COUNTER A SER RECEBIDO -> QUANDO EU O RECEBI | KEEPER USA PARA DAR TIMEOUT
    u64 rcounter; // IN_PING | COUNTER DO ULTIMO PING DO PEER (PARA CONFIRMAR SE É SEQUENCIAL E NÃO REPETIDO)
    u64 last;     // KEEPER
    u64 sent;     // KEEPER | QUANDO ENVIEI O ULTIMO PING
    u64 acks;     // KEEPER - HISTORY
    u16 rtt;      // KEEPER WRITE / OUT READ  <<---- VAI TER QUE ENFIAR ESSA PORRA ENTÃO DENTRO DO CACHE LINE DO SKEL, OU NO NODE
    u8  rtt_index;
    u8  dhcp; // ADDR/DHCP ID
    u8  tos;
    u8  ttl;
// 32 -- KEEPER / PING
    skb_s* _skb;
    path_s* next; // NA LISTA DE PINGS - ONLY VALID WHEN PATH STATUS >= K_UNSTABLE
    u16 reserved32;
    u8  sPortIndex;
    u8  sPortsN;
    u8  dPortIndex;
    u8  dPortsN;
// SÓ PODE USAR PSTATS SE TEVE PATH-> !!!
    volatile stat_s* pstats; // TODO: UMA ARRAY AQUI MESMO?
    // TODO: SEMANTICA DE memset(PATH, 0) AO DELETAR O PATH, E ESSES STATS
// 48 -- RO (ALMOST) - KEEPER ON START
    u64 since;
    u32 starts;
    char name [PATH_NAME_SIZE];
    u16 sPorts [PATH_PORTS_N]; // EM BIG ENDIAN
    u16 dPorts [PATH_PORTS_N];
// 112 -- RO - IN
    pkt_s skel;
// 64 -- KEEPER
    u32 rtts [PATH_RTTS_N];
};

//
BUILD_ASSERT(offsetof(path_s,   info) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(path_s,   _skb) % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(path_s, sPorts) % CACHE_LINE_SIZE == 0);

BUILD_ASSERT(sizeof(path_s) == PATH_SIZE);

//
BUILD_ASSERT(PATH_RTT_MIN     >= 1);
BUILD_ASSERT(PATH_RTT_VAR_MIN >= 1);

BUILD_ASSERT((typeof(((path_s*)NULL)->nid))         NID_MAX          == NID_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pid))         PID_MAX          == PID_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt))         PATH_RTT_MAX     == PATH_RTT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt_min))     PATH_RTT_MAX     == PATH_RTT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt_max))     PATH_RTT_MAX     == PATH_RTT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt_var))     PATH_RTT_VAR_MAX == PATH_RTT_VAR_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->timeout))     PATH_TIMEOUT_MAX == PATH_TIMEOUT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->info))        P_INFO           == P_INFO);
BUILD_ASSERT((typeof(((path_s*)NULL)->info))        K_ESTABLISHED    == K_ESTABLISHED);
BUILD_ASSERT((typeof(((path_s*)NULL)->weight))      PATH_WEIGHT_MAX  == PATH_WEIGHT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->weight_acks)) ACKS_N           == ACKS_N);
BUILD_ASSERT((typeof(((path_s*)NULL)->sPortsN))     PATH_PORTS_N     == PATH_PORTS_N);
BUILD_ASSERT((typeof(((path_s*)NULL)->dPortsN))     PATH_PORTS_N     == PATH_PORTS_N);
BUILD_ASSERT((typeof(((path_s*)NULL)->sPortIndex))  (PATH_PORTS_N-1) == (PATH_PORTS_N-1));
BUILD_ASSERT((typeof(((path_s*)NULL)->dPortIndex))  (PATH_PORTS_N-1) == (PATH_PORTS_N-1));

//
BUILD_ASSERT((sizeof(((path_s*)NULL)->acks)*8) == ACKS_N);

// A ARRAY DE OUTPUT É PARA NAO PRECISAR DE LOCK
#define O_PAIRS_ALL     17
#define O_PAIRS_DYNAMIC 16 // TEM QUE SER DAR OVERFLOW CONFORME NODE->OCYCLE
#define O_PAIR_PING     16

// A ARRAY DE INPUT É PARA AGUENTAR DEMORA/PERDA DE PACOTES
// A CADA INTERVALO SAO ENVIADOS UM PING POR PATH *ATIVO*
#define I_PAIRS_ALL     256 // USA TODOS OS VALORES DO HDR pkt->version E ASSIM NAO PRECISA VERIFICAR
#define I_PAIRS_DYNAMIC 255 // NAO TEM QUE CONSIDERAR O OVERFLOW POIS NO KEEPER NAO PRECISA SER ATOMIC
#define I_PAIR_PING     255 // TEM QUE CABER NO PKT->VERSION

//
#define OPATH_0 0x0001000100010001ULL
#define IPATH_0 0x0001U
#define KPATH_0 0x0001U

#define OPATHS  0xFFFFFFFFFFFFFFFFULL
#define IPATHS  0xFFFFU
#define KPATHS  0xFFFFU

#define OPATH(pid) (OPATH_0 << (pid))
#define IPATH(pid) (IPATH_0 << (pid))
#define KPATH(pid) (KPATH_0 << (pid))

// TODO: USE ATTRIBUTES ALIGNMENT CACHE
// THIS IS NOT CLEARED ON START
#define NODE_SIZE_INIT offsetof(node_s, oKeys)

struct node_s { // DEIXA TUDO NO MESMO CACHE LINE PARA A ITERACAO DO KEEPER
// 64 -- KEEPER / IN / OUT
    u64 opaths; // PATHS ALLOWED TO OUT
    u16 kpaths; // PATHS TO KEEP
    u16 ipaths; // PATHS ALLOWED TO IN
    u16 mtu;
    u16 weights;
    u64 lcounter;
    u64 rcounter;
    u64* conns; // JIFFIES (60) | PID (4) -- GROUPS OF CONNECTIONS WITH SAME HASH
    u32 connsN:24, // O OUT PRECISA DISSO  ((((1 << node->order) * PAGE_SIZE) - offsetof(node_s, conns)) / sizeof(conn_s))
        info:8;
    u8  iCycle; // TODO: CONNS COM __ATOMIC_SEQ_CST
    u8  oCycle; // O OVERFLOW TEM QUE SER MULTIPLO DE O_PAIRS_DYNAMIC
    u8  oIndex; // QUAL SERA USADO PARA ENCRIPTAR
    u8  oVersions [O_PAIRS_ALL];
// 32 -- RO - KEEPER/CMD
    node_s** ptr;
    node_s* next;
    u16 nid;
    u16 gw;
    u32 reserved32;
    net_device_s* dev; // TODO: USA MUITO NO IN, E TALVEZ NO OUT E NO CMD
// 32 -- RO - NAME
    char name [NODE_NAME_SIZE];
// 5120 -- PATHS
    path_s paths [PATHS_N];
// 16384 --
    volatile stat_s pstats [PATHS_N] [64]; // TODO: DIMINUIR ISSO
// ---------------------- NODE_SIZE_INIT -----------------------------
// 1024 + 64 -- KEEPER/OUT READ, IN WRITE
    u64 oKeys [O_PAIRS_ALL] [KEYS_N];
// 16384 -- IN READ, KEEPER WRITE
    u64 iKeys [I_PAIRS_ALL] [KEYS_N];
// 65536 -- RO
    u64 secret [SECRET_PAIRS_N] [KEYS_N]; // TODO: PARA SER DINAMICO, TERA QUE RESETAR TAMBEM O node->paths[*].pstats
};

BUILD_ASSERT(sizeof(((node_s*)NULL)->pstats)
         >= (sizeof(((node_s*)NULL)->pstats[0][0]) * PSTATS_N));

//
BUILD_ASSERT(sizeof(((node_s*)NULL)->oKeys)  == 1088);
BUILD_ASSERT(sizeof(((node_s*)NULL)->iKeys)  == 16384);
BUILD_ASSERT(sizeof(((node_s*)NULL)->secret) == 65536);
BUILD_ASSERT(sizeof(((node_s*)NULL)->paths)  == 5120);
BUILD_ASSERT(sizeof(((node_s*)NULL)->pstats) == 16384);
BUILD_ASSERT(sizeof(node_s)                  == 104640);

//
BUILD_ASSERT(sizeof(((node_s*)NULL)->secret) == SECRET_SIZE);

BUILD_ASSERT(offsetof(node_s, opaths)   % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, ptr)      % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, paths)    % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, pstats)   % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, oKeys)    % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, iKeys)    % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, secret)   % CACHE_LINE_SIZE == 0);

// THE TYPES MUST BE ABLE TO HOLD THE VALUES
BUILD_ASSERT((typeof(((node_s*)NULL)->nid))NID_MAX == NID_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->mtu))MTU_MAX == MTU_MAX);
//BUILD_ASSERT((typeof(((node_s*)NULL)->info))N_INFO == N_INFO);
//BUILD_ASSERT((typeof(((node_s*)NULL)->connsN))CONNS_N_MAX == CONNS_N_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->weights))(PATHS_N * PATH_WEIGHT_MAX) == (PATHS_N * PATH_WEIGHT_MAX));

BUILD_ASSERT((typeof(((node_s*)NULL)->kpaths))KPATH(PID_MAX) == KPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->opaths))OPATH(PID_MAX) == OPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->ipaths))IPATH(PID_MAX) == IPATH(PID_MAX));

BUILD_ASSERT((typeof(((node_s*)NULL)->kpaths))KPATHS == KPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->opaths))OPATHS == OPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->ipaths))IPATHS == IPATHS);

#define node_is_off(node)  (((uintptr_t)(node)) & 1)

#define nodes_set_on(nid, node)  __atomic_store_n(&nodes[nid], node, __ATOMIC_SEQ_CST)
#define nodes_set_off(nid, node) __atomic_store_n(&nodes[nid], (node_s*)((uintptr_t)(node) | 1), __ATOMIC_SEQ_CST)

// GETS A NODE WHILE THE LOCK IS NOT HOLD
// NOTE: CALLER MUST THEN HANDLE THE OFF BIT
#define nodes_get_unlocked(nid) __atomic_load_n(&nodes[nid], __ATOMIC_SEQ_CST)

// GETS A NODE WHILE THE LOCK IS HOLD, WITH THE STATUS
// NOTE: CALLER MUST THEN HANDLE THE OFF BIT
#define nodes_get_locked_suspended(nid) (nodes[nid])

// GETS A NODE WHILE THE LOCK IS HOLD, WITHOUT THE STATUS
#if 1
#define nodes_get_locked_unsuspended(nid) ((node_s*)((uintptr_t)nodes[nid] & ~((uintptr_t)1)))
#else
#define nodes_get_locked_unsuspended(nid) ((node_s*)(((uintptr_t)nodes[nid] >> 1) << 1))
#endif

#define __link(o, ptr_to_next) { \
        if ((o->next = (ptr_to_next))) { \
             o->next->ptr = &o->next; \
        }  *(o->ptr = &(ptr_to_next)) = o; \
    }

// NOTE: O->NEXT FICARA INVALIDO
#define __unlink(o) { \
        if ((*o->ptr = o->next)) { \
            (*o->ptr)->ptr = o->ptr; \
        }     o->ptr = NULL; \
    }

//
#define path_is_eth(path)  (path->skel.type & __ETH)
#define path_is_vlan(path) (path->skel.type & __VLAN)
#define path_is_ppp(path)  (path->skel.type & __PPP)
#define path_is_ip4(path)  (path->skel.type & __IP4)
#define path_is_ip6(path)  (path->skel.type & __IP6)
#define path_is_udp(path)  (path->skel.type & __UDP)
#define path_is_tcp(path)  (path->skel.type & __TCP)

#define path_is_udp_tcp(path) (path->skel.type & (__UDP | __TCP))

//
static inline u64   swap64 (const u64 x) { const uint q = popcount64(x); return (x >> q) | (x << (64 - q)); }
static inline u64 unswap64 (const u64 x) { const uint q = popcount64(x); return (x << q) | (x >> (64 - q)); }

static inline u64 __u64x8_sum_reduced (const u64x8 V[], const uint n);

DEFINE_SPINLOCK(xlock);

static volatile ports_t ports [PORTS_N];
static volatile stat_s dstats           [DSTATS_N];
static volatile stat_s nstats [NODES_N] [NSTATS_N];
static net_device_s* xgw;
static node_s* knodes;
static u16 nodeSelf;
static u8 gwsN;
static u16 gws [GWS_N]; // TODO: PODE DEIXAR DUAS ARRAYS E MODIFICAR A QUE NAO ESTA SENDO USADA
static node_s* volatile nodes [NODES_N];
#ifdef CONFIG_XGW_NMAP
static volatile u16 nmap [NODES_N];
#endif

// NEED TO BE SEPARATE
//    - SO IT CAN BE USET WITHOUT THE LOCK
//    - SO IT CAN BE USET WITH INTERRUPTS ENABLED
//    - SO IT CAN BE DONE ONCE
//    - SO IT CAN BE DONE PER INTERFACE HASH
static path_s* pings [PING_QUEUES_N];

static netdev_tx_t out (skb_s* const skb, net_device_s* const dev);
static void paged_free (void* const a, const size_t size);
static void* paged_alloc (const size_t size);
static void __cold_as_ice __optimize_size stats_print (void);
static void __cold_as_ice __optimize_size dev_setup (net_device_s* const dev);
static inline void ports_enable (const uint port);
static inline void ports_disable (const uint port);
static inline ports_t ports_is_enabled (const uint port);

// EXPOSED TO KERNEL
// net/core/dev.c WILL USE US
#define in xgw_dev_in

int in (skb_s* const skb);

#ifdef CONFIG_XGW_BEEP
#include "beep.c"
#endif
#include "pkt.c"
#include "crypto.c"
#include "out.c"
#include "in.c"
#include "keeper.c"
#include "stats.c"
#include "dev.c"
#include "cmd.c"

static inline u64 __u64x8_sum_reduced (const u64x8 V[], const uint n) {

    u64x8 v = { 0, 0, 0, 0, 0, 0, 0, 0 };

    for (uint i = 0; i != n; i++)
        v += V[i];

    return v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
}

// TODO: SO APRENDER UM PATH SE TAL PORTA ESTIVER CONFIGURADA NELE
static inline void ports_enable (const uint port) {

    PORTS_W |= PORTS_B;
}

static inline void ports_disable (const uint port) {

    PORTS_W &= ~PORTS_B;
}

static inline ports_t ports_is_enabled (const uint port) {

    return PORTS_W & PORTS_B;
}

static inline uint paged_order (const size_t size) {

    uint real = PAGE_SIZE;

    while (real < size)
           real <<= 1;

    return __ctz(real / PAGE_SIZE);
}

static void paged_free (void* const a, const size_t size) {

    free_pages((uintptr_t)a, paged_order(size));
}

static void* paged_alloc (const size_t size) {

    return (void*)__get_free_pages(GFP_NOWAIT, paged_order(size));
}


/*

 - pode fazer isso deixando de verificar o hash no TCP
    e trocando a porta dst no input para CONFIG_XGW_PROXY_PORT
    e trocando a porta src no output para CONFIG_XGW_PROXY_PORT

 - pode fazer isso forcando a porta CONFIG_XGW_PROXY_PORT ao verificar o bind hash tables
        e mantendo as portas originais
*/

// EM MILISEGUNDOS E NAO JIFIFES

// TERMINADO EM 1: SEM IN/OUT (ESTA DISABLED)
// NULL -> NAO TEM, OU ESTA SENDO DELETADO

// vai ter que retirar o erro node_is_self :S ?
//  ou nao vai poder setar o self comoum que ja existe
// e nem crar um que seja o self

static struct proc_ops xgwProcOps = {
    .proc_write = cmd,
};

static int __init xgw_init (void) {

    //BUILD_ASSERT(sizeof(dhcp_s) == DHCP_SIZE);

    //BUILD_ASSERT(sizeof(((node_s*)NULL->secret) == SECRET_SIZE);

    //
    BUILD_ASSERT( ( ((uintptr_t)0xffffffffffffffffULL) & (~(uintptr_t)1) ) == (0xffffffffffffffffULL ^ 1) );

    printk("XGW: INIT KEEPER INTERVAL %d\n", KEEPER_INTERVAL);
    printk("XGW: V4 PREFIX %08llX WIDTH %u/%u\n", (uintll)V4_PREFIX, V4_WIDTH_PREFIX, V4_WIDTH_NODE);
    printk("XGW: V6 PREFIX %016llX WIDTH %u/%u\n", (uintll)V6_PREFIX, V6_WIDTH_PREFIX, V6_WIDTH_NODE);

    // INITIALIZE EVERYTHING

    // TODO:
    nodeSelf = 0;

    gwsN = 0;

    _xrnd = 0;

    knodes = NULL;

    memset(pings,  0, sizeof(pings));
    memset(gws,  0, sizeof(gws));
    memset((void*)ports,  0, sizeof(ports));
    memset((void*)nodes,  0, sizeof(nodes));
    memset((void*)&dstats, 0, sizeof(dstats));
    memset((void*)&nstats, 0, sizeof(nstats));

#ifdef CONFIG_XGW_NMAP
    //
    for (int i = 0; i != NODES_N; i++)
        nmap[i] = i;
#endif

    // CREATE THE VIRTUAL INTERFACE
    xgw = alloc_netdev(0, "xgw", NET_NAME_USER, dev_setup);

    if (xgw == NULL) {
        printk("XGW: FAILED TO ALLOCATE\n");
        return -1;
    }

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(xgw)) {
        printk("XGW: CREATE FAILED TO REGISTER\n");
        return -1;
    }

#ifdef CONFIG_XGW_BEEP
    proc_create("beep", 0600, NULL, &beepProcOps);
#endif

    // LAUNCH KEEPER
    kTimer.expires = jiffies + 10*HZ;

    add_timer(&kTimer);

    // EXPOSE CMD
    proc_create("xgw", 0600, NULL, &xgwProcOps);

    return 0;
}

late_initcall(xgw_init);

// TODO: REVIEW ALL RESTRICT
