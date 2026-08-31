/*

	SETARO NET_SKB_PAD COMO AO MENOS 128
*/

// !!!!!! TODO: XGW TO XGW REDIRECT WITHOUT GOING THROUGH IP STACK

// EXPOSED TO KERNEL
// net/core/dev.c WILL USE US
#define in xgw_dev_in

#if 1
#define BUILD_ASSERT(c) _Static_assert((c), #c)
#else
#define BUILD_ASSERT(c)
#endif

#ifdef CONFIG_XGW_ASSERT
#define ASSERT(c) ({ if (unlikely(!(c))) printk("XGW: %s:%d: ASSERT FAILED: %s\n", __FILE__, __LINE__, #c); })
#elif 1
#define ASSERT(c) __attribute__((assume(c)))
#else
#define ASSERT(c) ({})
#endif

#define CACHE_LINE_SIZE 64

#ifdef CONFIG_XGW_GATEWAY
#define XGW_TCP_PROXY_MARK_4 0x25440000U
#define XGW_TCP_PROXY_MARK_6 0x25660000U
#endif

// QUANTO MAIS INTERVALOS AGUENTA MAIS TEMPO DE FALHAS DE CONEXAO SEM TER QUE RENEGOCIAR E EXPOR AS PRESHAREDS
// QUANTO MAIS INTERVALOS MENOS PROBABILIDADE DA RESINCRONIZACAO DE L/R COUNTERS SOBRESCREVER IKEYS ATUAIS

// A XGW ADDRESS IS COMPOSED OF
// PREFIX | NODE | SUB

#include "base.h"

#if     NET_SKBUFF_DATA_USES_OFFSET != 1
#error  NET_SKBUFF_DATA_USES_OFFSET
#endif

// 192.0.0.0/24
#define V4_PREFIX 0xC0000000U
#define V4_WIDTH_PREFIX 24
#define V4_WIDTH_NODE 8

// fccc::/16         -> XGW'S NETWORK
// fccc:NODE::/32    -> NODE'S NETWORK
#define V6_PREFIX 0xFCCC000000000000ULL
#define V6_WIDTH_PREFIX 16
#define V6_WIDTH_NODE 16

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

#define LTIME_DIFF_RTIME(ltime, rtime) ((s64)(ltime) - (s64)(rtime))
#define LTIME(rtime, tdiff) ((u64)((rtime) + (tdiff)))
#define RTIME(ltime, tdiff) ((u64)((ltime) - (tdiff)))

// TODO: AUMENTAR ESTE PMASK_MIN, E AI O RTIME_MIN SERA 0
enum PMASK : u64 {
     PMASK_MIN = 0x0000000000010000ULL,
     PMASK_MAX = 0x2000000000000000ULL,
};

enum ANSWERED : u64 {
     ANSWERED_LISTENING  =    0,
     ANSWERED_ACCEPTING  =    1,
     ANSWERED_CONNECTING = 2048, // TEM QUE SER GRANDE SUFICIENTE PARA QUE ((path->answered - path->asked) > RTT_MAX)
};

// REAL TIME (KTIME) (~2 YEARS IN MS)
enum RTIME : u64 {
     RTIME_MIN = 8192,
     RTIME_MAX = 0x1800000000ULL,
};

//
enum PTIME : u64 {
     PTIME_MIN = PMASK_MIN + RTIME_MIN,
     PTIME_MAX = PMASK_MAX + RTIME_MAX,
};

// MAX DIFFERENCE FROM LOCAL PTIME TO PEER PTIME
enum TTIME : s64 {
     TDIFF_MIN = (s64)PTIME_MIN - (s64)PTIME_MAX,
     TDIFF_MAX = (s64)PTIME_MAX - (s64)PTIME_MIN,
};

typedef struct pkt_s  pkt_s;
typedef struct ping_s ping_s;
typedef struct path_s path_s;
typedef struct node_s node_s;
typedef struct stat_s stat_s;

typedef struct ip4_s ip4_s;
typedef struct ip6_s ip6_s;

typedef struct hdr_ip4_s   hdr_ip4_s;
typedef struct hdr_ip6_s   hdr_ip6_s;
typedef struct hdr_udp_s   hdr_udp_s;
typedef struct hdr_tcp_s   hdr_tcp_s;
typedef struct hdr_eth_s   hdr_eth_s;
typedef struct hdr_vlan_s  hdr_vlan_s;
typedef struct hdr_ppp_s   hdr_ppp_s;

typedef struct encap_raw_s              encap_raw_s;
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

#define PORTS_W (ports[port >> PORTS_SHIFT])
#define PORTS_B (1 << (port & PORTS_MASK))

typedef uint ports_t;

enum : uint {

    // TAMANHO DO NOSSO CABECALHO
    PKT_X_SIZE = 24,

    PKT_ALIGN_WORDS =  2,
    PKT_ALIGN_SIZE  = PKT_ALIGN_WORDS * sizeof(u64),

    // É ISSO QUE TEM QUE SER RETIRADO DO MTU DA INTERFACE XGW
    // (E TAMBEM OS DEMAIS ENCAPSULAMENTOS DO PHYS)
    XGW_MTU_OVERHEAD = PKT_X_SIZE + PKT_ALIGN_SIZE,

    // MAXIMUM SIZE
    // (? + ETH + VLAN + PPPOE + IP6 + TCP)
    // (2 + 14  + 4    + 8     + 40  + 20 )
    ENCAP_SIZE = 88,

    // ENCAP_SIZE + sizeof(hdr_x_s)
    PKT_SIZE = 112,
};

// TODO: XGW_PAYLOAD_MAX TEM QUE SER 65536, E PKT->DSIZE ENCODED COM -1 E DECODED COM +1
enum XGW_PAYLOAD : uint {
     XGW_PAYLOAD_MIN =     28, // AN EMPTY IPV4/UDP
     XGW_PAYLOAD_MAX = 0xFFFF, // MUST FIT ON PKT->SIZE
};

#define PKT_DATA(pkt) PTR(&(pkt)->p[PKT_ALIGN_WORDS])

// IP TOS
enum TOS : u8 {
     TOS_MAX = 0xFF,
};

// IP TTL
enum TTL : u8 {
     TTL_MIN = 0x01,
     TTL_MAX = 0xFF,
};

// TODO:
enum IPPROTO : u8 {
     IPPROTO_XGW = 0x99,
};

// TODO:
enum ETH_P : u16 {
     ETH_P_XGW = 0x2562,
};

// HEADERS
struct hdr_eth_s {
    u8  dmac [ETH_ALEN];
    u8  smac [ETH_ALEN];
    u16 proto;
};

struct hdr_vlan_s {
    u16 id;
    u16 proto;
};

enum PPP_PROTO : u16 {
     PPP_PROTO_IP4   = 0x0021,
     PPP_PROTO_IP6   = 0x0057,
     PPP_PROTO_LCP   = 0xC021, // Protocol: Link Control Protocol (0xc021)
     PPP_PROTO_PAP   = 0xC023, // Protocol: Password Authentication Protocol (0xc023)
     PPP_PROTO_IPCP4 = 0x8021, // Protocol: Internet Protocol Control Protocol (0x8021)
     PPP_PROTO_IPCP6 = 0x8057, // Protocol: IPv6 Control Protocol (0x8057)
     PPP_PROTO_XGW   = 0x2562,
};

struct hdr_ppp_s {
    u16 code; // VERSION (0x1) | TYPE (0x1) | CODE (0x00) -> 0x1100
    u16 session;
    u16 size; // IP SIZE + 2
    u16 proto;
};

struct hdr_ip4_s {
    u8  version;
    u8  tos;
    u16 size;
    u16 id;
    u16 frag;
    u8  ttl;
    u8  proto;
    u16 cksum;
    u8  saddr [4];
    u8  daddr [4];
};

struct hdr_ip6_s {
    u8  version;
    u8  tos; // TODO: O IPV6 TOS TEM QUE SER UM BITFIELD
    u16 flow;
    u16 size;
    u8  proto;
    u8  ttl;
    u16 saddr [8];
    u16 daddr [8];
};

struct hdr_tcp_s {
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
    u16 flags;
    u16 window;
    u16 cksum;
    u16 urg;
};

struct hdr_udp_s {
    u16 sport;
    u16 dport;
    u16 size;
    u16 cksum;
};

// PAYLOAD
// PURPOSE: READ VERSION, SIZE, NAT, COMPUTE CHECKSUMS

struct __packed ip4_s {
    u8  version;
    u8  tos;
    u16 size;
    u16 id;
    u16 frag;
    u8  ttl;
    u8  proto;
    u16 cksum;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct __packed ip6_s {
    u32 flow;
    u16 size; // MAS É SO DO PAYLOAD
    u8  proto;
    u8  ttl;
    u64 saddr [2];
    u64 daddr [2];
    u16 sport;
    u16 dport;
};

struct hdr_x_s { // WIRE
    union {
        struct {
            u16 src;
            u16 dst;
            u8  path; // BEM NO MEIO PARA PROTEGE-LO NO HASHING
            u8  version;
            u16 dsize; // SIZE OF THE PAYLOAD
        };  u64 info;
    };
    u64 time; // DESTINATION'S TIME (NO CASO DO PONG, O PKT->TIME É O RAW PING->RTIME SENDO RESPONDIDO)
    u64 hash;
};

// ENCAPSULATION FLAGS
enum : u8 {

    __ETH  = 1 << 0,
    __VLAN = 1 << 1,
    __IP4  = 1 << 2,
    __IP6  = 1 << 3,
    __TCP  = 1 << 4,
    __UDP  = 1 << 5,
    __PPP  = 1 << 6,

    H_TYPES_N = 1 << 7,
};

// ENCAPSULATION TYPES
enum H_TYPE : u8 {
     H_TYPE_RAW              = 0,
     H_TYPE_IP4              = __IP4,
     H_TYPE_IP4_UDP          = __IP4  | __UDP,
     H_TYPE_IP4_TCP          = __IP4  | __TCP,
     H_TYPE_IP6              = __IP6,
     H_TYPE_IP6_UDP          = __IP6  | __UDP,
     H_TYPE_IP6_TCP          = __IP6  | __TCP,
     H_TYPE_ETH              = __ETH,
     H_TYPE_ETH_IP4          = __ETH  | __IP4,
     H_TYPE_ETH_IP4_UDP      = __ETH  | __IP4   | __UDP,
     H_TYPE_ETH_IP4_TCP      = __ETH  | __IP4   | __TCP,
     H_TYPE_ETH_IP6          = __ETH  | __IP6,
     H_TYPE_ETH_IP6_UDP      = __ETH  | __IP6   | __UDP,
     H_TYPE_ETH_IP6_TCP      = __ETH  | __IP6   | __TCP,
     H_TYPE_ETH_VLAN         = __ETH  | __VLAN,
     H_TYPE_ETH_VLAN_IP4     = __ETH  | __VLAN  | __IP4,
     H_TYPE_ETH_VLAN_IP4_UDP = __ETH  | __VLAN  | __IP4  | __UDP,
     H_TYPE_ETH_VLAN_IP4_TCP = __ETH  | __VLAN  | __IP4  | __TCP,
     H_TYPE_ETH_VLAN_IP6     = __ETH  | __VLAN  | __IP6,
     H_TYPE_ETH_VLAN_IP6_UDP = __ETH  | __VLAN  | __IP6  | __UDP,
     H_TYPE_ETH_VLAN_IP6_TCP = __ETH  | __VLAN  | __IP6  | __TCP,
     H_TYPE_ETH_VLAN_PPP     = __ETH  | __VLAN  | __PPP,
     H_TYPE_ETH_VLAN_PPP_IP4 = __ETH  | __VLAN  | __PPP  | __IP4,
     H_TYPE_ETH_VLAN_PPP_IP6 = __ETH  | __VLAN  | __PPP  | __IP6,
     H_TYPE_ETH_PPP          = __ETH  | __PPP,
     H_TYPE_ETH_PPP_IP4      = __ETH  | __PPP   | __IP4,
     H_TYPE_ETH_PPP_IP6      = __ETH  | __PPP   | __IP6,
};

// ENCAPSULATION OFFSETS
// THE OFFSET FROM THE PKT TO THE HEADERS
enum H_OFFSET : uint {
     H_OFFSET_RAW              = PKT_SIZE - sizeof(hdr_x_s),
     H_OFFSET_ETH              = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s),
     H_OFFSET_ETH_IP4          = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ip4_s),
     H_OFFSET_ETH_IP6          = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ip6_s),
     H_OFFSET_ETH_IP4_UDP      = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ip4_s)   - sizeof(hdr_udp_s),
     H_OFFSET_ETH_IP6_UDP      = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ip6_s)   - sizeof(hdr_udp_s),
     H_OFFSET_ETH_IP4_TCP      = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ip4_s)   - sizeof(hdr_tcp_s),
     H_OFFSET_ETH_IP6_TCP      = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ip6_s)   - sizeof(hdr_tcp_s),
     H_OFFSET_ETH_VLAN         = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_vlan_s),
     H_OFFSET_ETH_VLAN_IP4     = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_vlan_s)  - sizeof(hdr_ip4_s),
     H_OFFSET_ETH_VLAN_IP6     = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_vlan_s)  - sizeof(hdr_ip6_s),
     H_OFFSET_ETH_VLAN_IP4_UDP = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_vlan_s)  - sizeof(hdr_ip4_s)   - sizeof(hdr_udp_s),
     H_OFFSET_ETH_VLAN_IP6_UDP = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_vlan_s)  - sizeof(hdr_ip6_s)   - sizeof(hdr_udp_s),
     H_OFFSET_ETH_VLAN_IP4_TCP = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_vlan_s)  - sizeof(hdr_ip4_s)   - sizeof(hdr_tcp_s),
     H_OFFSET_ETH_VLAN_IP6_TCP = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_vlan_s)  - sizeof(hdr_ip6_s)   - sizeof(hdr_tcp_s),
     H_OFFSET_ETH_VLAN_PPP     = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ppp_s)   - sizeof(hdr_vlan_s),
     H_OFFSET_ETH_VLAN_PPP_IP4 = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ppp_s)   - sizeof(hdr_vlan_s)  - sizeof(hdr_ip4_s),
     H_OFFSET_ETH_VLAN_PPP_IP6 = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ppp_s)   - sizeof(hdr_vlan_s)  - sizeof(hdr_ip6_s),
     H_OFFSET_ETH_PPP          = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ppp_s),
     H_OFFSET_ETH_PPP_IP4      = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ppp_s)   - sizeof(hdr_ip4_s),
     H_OFFSET_ETH_PPP_IP6      = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_eth_s)  - sizeof(hdr_ppp_s)   - sizeof(hdr_ip6_s),
     H_OFFSET_IP4              = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_ip4_s),
     H_OFFSET_IP6              = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_ip6_s),
     H_OFFSET_IP4_UDP          = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_ip4_s)  - sizeof(hdr_udp_s),
     H_OFFSET_IP4_TCP          = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_ip4_s)  - sizeof(hdr_tcp_s),
     H_OFFSET_IP6_UDP          = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_ip6_s)  - sizeof(hdr_udp_s),
     H_OFFSET_IP6_TCP          = PKT_SIZE - sizeof(hdr_x_s)  - sizeof(hdr_ip6_s)  - sizeof(hdr_tcp_s),
};

#define __

// TODO: __packed? ARM?
struct pkt_s {
    union { // ENCAP
        struct encap_raw_s              { char _ [H_OFFSET_RAW              ]; __             __         __    __        __   __        __   __        __   } encap_raw;
        struct encap_eth_s              { char _ [H_OFFSET_ETH              ]; hdr_eth_s eth; __         __    __        __   __        __   __        __   } encap_eth;
        struct encap_eth_ip4_s          { char _ [H_OFFSET_ETH_IP4          ]; hdr_eth_s eth; __         __    __        __   hdr_ip4_s ip4; __        __   } encap_eth_ip4;
        struct encap_eth_ip6_s          { char _ [H_OFFSET_ETH_IP6          ]; hdr_eth_s eth; __         __    __        __   hdr_ip6_s ip6; __        __   } encap_eth_ip6;
        struct encap_eth_ip4_udp_s      { char _ [H_OFFSET_ETH_IP4_UDP      ]; hdr_eth_s eth; __         __    __        __   hdr_ip4_s ip4; hdr_udp_s udp; } encap_eth_ip4_udp;
        struct encap_eth_ip6_udp_s      { char _ [H_OFFSET_ETH_IP6_UDP      ]; hdr_eth_s eth; __         __    __        __   hdr_ip6_s ip6; hdr_udp_s udp; } encap_eth_ip6_udp;
        struct encap_eth_vlan_s         { char _ [H_OFFSET_ETH_VLAN         ]; hdr_eth_s eth; hdr_vlan_s vlan; __        __   __        __   __        __   } encap_eth_vlan;
        struct encap_eth_vlan_ip4_s     { char _ [H_OFFSET_ETH_VLAN_IP4     ]; hdr_eth_s eth; hdr_vlan_s vlan; __        __   hdr_ip4_s ip4; __        __   } encap_eth_vlan_ip4;
        struct encap_eth_vlan_ip6_s     { char _ [H_OFFSET_ETH_VLAN_IP6     ]; hdr_eth_s eth; hdr_vlan_s vlan; __        __   hdr_ip6_s ip6; __        __   } encap_eth_vlan_ip6;
        struct encap_eth_vlan_ip4_udp_s { char _ [H_OFFSET_ETH_VLAN_IP4_UDP ]; hdr_eth_s eth; hdr_vlan_s vlan; __        __   hdr_ip4_s ip4; hdr_udp_s udp; } encap_eth_vlan_ip4_udp;
        struct encap_eth_vlan_ip6_udp_s { char _ [H_OFFSET_ETH_VLAN_IP6_UDP ]; hdr_eth_s eth; hdr_vlan_s vlan; __        __   hdr_ip6_s ip6; hdr_udp_s udp; } encap_eth_vlan_ip6_udp;
        struct encap_eth_vlan_ppp_s     { char _ [H_OFFSET_ETH_VLAN_PPP     ]; hdr_eth_s eth; hdr_vlan_s vlan; hdr_ppp_s ppp; __        __   __        __   } encap_eth_vlan_ppp;
        struct encap_eth_vlan_ppp_ip4_s { char _ [H_OFFSET_ETH_VLAN_PPP_IP4 ]; hdr_eth_s eth; hdr_vlan_s vlan; hdr_ppp_s ppp; hdr_ip4_s ip4; __        __   } encap_eth_vlan_ppp_ip4;
        struct encap_eth_vlan_ppp_ip6_s { char _ [H_OFFSET_ETH_VLAN_PPP_IP6 ]; hdr_eth_s eth; hdr_vlan_s vlan; hdr_ppp_s ppp; hdr_ip6_s ip6; __        __   } encap_eth_vlan_ppp_ip6;
        struct encap_eth_ppp_s          { char _ [H_OFFSET_ETH_PPP          ]; hdr_eth_s eth; __         __    hdr_ppp_s ppp; __        __   __        __   } encap_eth_ppp;
        struct encap_eth_ppp_ip4_s      { char _ [H_OFFSET_ETH_PPP_IP4      ]; hdr_eth_s eth; __         __    hdr_ppp_s ppp; hdr_ip4_s ip4; __        __   } encap_eth_ppp_ip4;
        struct encap_eth_ppp_ip6_s      { char _ [H_OFFSET_ETH_PPP_IP6      ]; hdr_eth_s eth; __         __    hdr_ppp_s ppp; hdr_ip6_s ip6; __        __   } encap_eth_ppp_ip6;
        struct encap_ip4_s              { char _ [H_OFFSET_IP4              ]; __        __   __         __    __        __   hdr_ip4_s ip4; __        __   } encap_ip4;
        struct encap_ip6_s              { char _ [H_OFFSET_IP6              ]; __        __   __         __    __        __   hdr_ip6_s ip6; __        __   } encap_ip6;
        struct encap_ip4_udp_s          { char _ [H_OFFSET_IP4_UDP          ]; __        __   __         __    __        __   hdr_ip4_s ip4; hdr_udp_s udp; } encap_ip4_udp;
        struct encap_ip4_tcp_s          { char _ [H_OFFSET_IP4_TCP          ]; __        __   __         __    __        __   hdr_ip4_s ip4; hdr_tcp_s tcp; } encap_ip4_tcp;
        struct encap_ip6_udp_s          { char _ [H_OFFSET_IP6_UDP          ]; __        __   __         __    __        __   hdr_ip6_s ip6; hdr_udp_s udp; } encap_ip6_udp;
        struct encap_ip6_tcp_s          { char _ [H_OFFSET_IP6_TCP          ]; __        __   __         __    __        __   hdr_ip6_s ip6; hdr_tcp_s tcp; } encap_ip6_tcp;
    };
    union { // X
        hdr_x_s x;
        struct { // RUNTIME
        // SRC, DST, PATH, VERSION, DSIZE
            u16 _src;
            u16 _dst;
            u8  _path;
            u8  _reserved;
            u16 _reserved16;
        // TIME
            net_device_s* phys;
        // HASH
            u8 type;
            u8 msize;          // skb->mac_len
            u8 moffset;        // PTR(pkt) + path->moffset -> SKB_MAC(skb)
            u8 Noffset;        // É NECESSARIO POIS QUANTO TEM VLAN O NETWORK OFFSET NAO APONTA PARA O IPV4 :S
            u8 noffset;        // PTR(pkt) + path->noffset -> SKB_NETWORK(skb)
            u8 toffset;        // PTR(pkt) + path->toffset -> SKB_TRANSPORT(skb)
            u16 protocol;      // skb->protocol
        };
    };
    u64 p []; // ALIGN | PING / PONG / PAYLOAD
};

// NOTE: ESSA PORRA DESSE ALINHAMENTO NAO ESTA DEIXANDO OS 64-BIT WORDS ALINHADOS PARA PROCESSARMOS
enum XGW_HEADROOM : uint {
     XGW_HEADROOM = sizeof(pkt_s) + (PKT_ALIGN_WORDS * sizeof(u64))
};

// TODO: TODOS OS ENCAP_S TEM QUE SER < ENCAP_MAX

#define PKT_ETH(pkt)   ((hdr_eth_s*)(PTR(pkt) + (pkt)->moffset))
#define PKT_VLAN(pkt) ((hdr_vlan_s*)(PTR(pkt) + (pkt)->noffset))
#define PKT_PPP(pkt)   ((hdr_ppp_s*)(PTR(pkt) + (pkt)->_reserved))
#define PKT_IP4(pkt)   ((hdr_ip4_s*)(PTR(pkt) + (pkt)->Noffset))
#define PKT_IP6(pkt)   ((hdr_ip6_s*)(PTR(pkt) + (pkt)->Noffset))
#define PKT_UDP(pkt)   ((hdr_udp_s*)(PTR(pkt) + (pkt)->toffset))
#define PKT_TCP(pkt)   ((hdr_tcp_s*)(PTR(pkt) + (pkt)->toffset))

//
enum : uint {

    //
    KEEPER_LAUNCH_DELAY_SECS = 4,

    //
    KEEPER_INTERVAL_MS = 900,
    KEEPER_INTERVAL_JIFFIES = (HZ * 9) / 10,

    // HASHEIA E AGRUPA POR INTERFACE INDEX
    // NOTE: SE MUDAR DE INTERFACE VAI TER QUE REMOVER DA LISTA PRIMEIRO, E SÓ DEPOIS JOGAR PARA OUTRO
    PING_QUEUES_N = 8,

    //
    MTU_MIN = XGW_PAYLOAD_MIN,
    MTU_MAX = XGW_PAYLOAD_MAX,

    //
    GWS_N = 8,

    RANDOM_LEN = 8,

    // ALL UDP PORTS
    UDP_PORTS_N = 65536,

    PORTS_WIDTH = 32,
    PORTS_SHIFT = 5,
    PORTS_MASK = 0b11111,

    PORTS_N = UDP_PORTS_N / PORTS_WIDTH,

    // HOW MANY WORDS IN A KEY
    K_LEN = 8,

    // THE SIZE, IN BYTES
    K_SIZE = K_LEN * sizeof(u64),

    // HOW MANY KEYS IN A SECRET
    SECRET_KEYS_N = 16384,

    //
    SECRET_SIZE = SECRET_KEYS_N * K_LEN * sizeof(u64),

    // DO QUAL DERIVAREMOS O SECRET
    PASSWORD_SIZE_MIN =     16,
    PASSWORD_SIZE_MAX = 524288,

    //
    PASSWORD_ROUNDS = 16,

    //
    PING_SIZE = 80,

    // KEYS, VERSION
    PING_RANDOMS_N = 9,

    //
    CONNS_MIN = CONFIG_XGW_CONNS_MIN,
    CONNS_MAX = CONFIG_XGW_CONNS_MAX,

    NODE_NAME_SIZE = 32,
    PATH_NAME_SIZE = 16, // "broad-bandz-p4u\0"

    NODES_N = 65536,

    // MANY PATHS ARE GOOD FOR:
    //  - TRAFFIC SHAPING
    //  - TRAFFIC RATING (ISP WON'T SEE A SINGLE CONNECTION WITH TOO MANY SPEED/CUMULATIVE USAGE)
    //  - MORE SECURITY (MORE CODES USED) --- NOT ANYMORE
    //  - MORE SECURITY (MORE KEYS GENERATED)
    //  - MORE SECURITY (MORE KEYS GENERATED THUS EXPIRATION IS FASTER)
    //  - RESILIENCY AGAINST BROKEN PATHS
    //  - NIC HASHING
    //  - RECEIVE CAN BE DISTRIBUTED TO MORE CPUS
    PATHS_N = 16,

    //
    NID_MAX = NODES_N - 1,
    PID_MAX = PATHS_N - 1,

    //
    PATH_PORTS_N = 4,

    // TODO: ASSERT( (typeof(node->weights))(PATH_WEIGHT_MAX * PATHS_N) == (PATH_WEIGHT_MAX * PATHS_N) )
    PATH_WEIGHT_MAX = 255,

    // HOW MANY ACKS IN HISTORY (WORD WIDTH IN BITS)
    ACKS_N = 64,

    RTT_MAX = 768,

    //
    RTT_VAR_MIN =    0,
    RTT_VAR_MAX = 2048,

    // TEM QUE CONSIDERAR A DEMORA PARA IR ATUALIZANDO O RTT
    // 20 * 300 = 6000 (MAX SKEW FOR RTT)
    // 6000 / 2 = 3000 (MAX SKEW FOR RTT/2)
    RTT_VAR_STEPS =  20,
    RTT_VAR_STEP  = 300,

    //
    RTT_VAR_MAX_INIT = RTT_VAR_MAX + (RTT_VAR_STEPS * RTT_VAR_STEP),

    //
    PATH_OADD_MIN =   1,
    PATH_OADD_MAX = 255,

    // TODO: REMOVER ISSO
    // TODO: N_OADD
    // TODO: CMD_NODE_OADD_SET
    PATH_OADD_DEFAULT = 64,

    //
    PATH_SIZE = 768,

    // FOR THE NODE
    NODE_WEIGHTS_MAX = PATHS_N * PATH_WEIGHT_MAX,
};

#if 0
struct ping_s {
    union {
        struct { // TODO: INCLUDE WORD(S) BEFORE K
            u64 k [K_LEN]; // SENDER'S IKEYS BEING TAUGHT (UNDEFINED ON PONG)
            u8 _ [7]; // TODO: INCLUDE WORD(S) AFTER K
            u8 ver; // SENDER'S IKEYS INDEX BEING REGISTERED (UNDEFINED ON PONG)
        };  u64 rnd [PING_RANDOMS_N];
    };      u64 time; // SENDER'S TIME (RAW)
};
#else
struct ping_s {
    u64 rnd [K_LEN];
    u8 _ [7];
    u8 ver;
    u64 time;
};
#endif

// STATISTICS
// NOTE: THOSE ORDERS MUST CONSIDER CACHE USAGE

// INTERFACE
// TODO: GLOBAL STATS VS PHYS STATS (PER ITFC INDEX)
enum DSTATS : uint {
     DSTATS_I_NOT_XGW, // PASS
     DSTATS_I_NON_LINEAR,
     DSTATS_I_INCOMPLETE,
     DSTATS_I_FROM_SELF,
     DSTATS_O_DATA_DOWN,
     DSTATS_O_DATA_NON_LINEAR,
     DSTATS_O_DATA_UNKNOWN,
     DSTATS_O_DATA_TO_SELF,
     DSTATS_O_DATA_NO_GW,
     DSTATS_O_DATA_SIZE_SMALL,
     DSTATS_O_DATA_SIZE_BIG,
     DSTATS_N
};

// NODE
enum NSTATS : uint {
     NSTATS_I_FORWARD, // PASS
     NSTATS_I_INEXIST,
     NSTATS_I_DISABLED,
     NSTATS_I_DOWN,
     NSTATS_I_PATH_INVALID,
     NSTATS_O_DATA_INEXIST,
     NSTATS_O_DATA_DISABLED,
     NSTATS_O_DATA_MTU_EXCEEDED,
     NSTATS_O_DATA_NO_PATH,
     NSTATS_N
};

// PATH
enum PSTATS : uint {
     PSTATS_I_DATA_GOOD, // PASS
     PSTATS_I_DATA_IP4_TRUNCATED,
     PSTATS_I_DATA_IP6_TRUNCATED,
     PSTATS_I_DISABLED,
     PSTATS_I_SIZE_SMALL,
     PSTATS_I_SIZE_TRUNCATED,
     PSTATS_I_SIZE_NOT_PING,
     PSTATS_I_HASH_MISMATCH,
     PSTATS_I_ESTABLISHED_REFUSE_SYN,
     PSTATS_I_CONNECTING_REQUIRE_PONG,
     PSTATS_I_LISTENING_SYN_TOO_MANY,
     PSTATS_I_LISTENING_SYN_WRONG,
     PSTATS_I_LISTENING_REFUSE_DATA_AND_PONG,
     PSTATS_I_ACCEPTING,
     PSTATS_I_LTIME_MISMATCH_SYN,
     PSTATS_I_LTIME_MISMATCH,
     PSTATS_I_RTIME_MISMATCH,
     PSTATS_I_SYN_ACK_RACED,
     PSTATS_I_PING_GOOD,
     PSTATS_I_PONG_GOOD,
     PSTATS_K_TIMEOUTS,
     PSTATS_O_PING_OK,
     PSTATS_O_PING_SKB_FAILED,
     PSTATS_O_PING_SEND_FAILED,
     PSTATS_O_DATA_OK,
     PSTATS_O_DATA_NO_HEADROOM,
     PSTATS_O_DATA_CKSUM_FAILED,
     PSTATS_O_DATA_FAIL,
     PSTATS_N
};

struct stat_s {
    u64 count;
    u64 bytes; // NOTE: ALGUNS STATS TERAO O COUNT/BYTES CONSIDERANDO O PACOTE REAL E NAO ENCAPSULADO
};

// TODO: OUT {ping, pong, data} _PHYS_DOWN
// TODO: OUT {ping, pong, data} _PHYS_NO_CARRIER

#define stat_inc_count(ptr)      __atomic_add_fetch(ptr, 1, __ATOMIC_RELAXED)
#define stat_inc_bytes(ptr, b)   __atomic_add_fetch(ptr, b, __ATOMIC_RELAXED)

#define ret_dev(i)  { stat = i; goto _ret_dev;  }
#define ret_node(i) { stat = i; goto _ret_node; }
#define ret_path(i) { stat = i; goto _ret_path; }

// NOTE: NAO ADIANTA SER MUITO LONGO POIS OS KEYS FICAM SENDO INUTILIZADOS
// NOTE: NAO ADIANTA SER MUITO LONGO POIS FICA SEM SINCRONIA
enum ACKS : u64 {
     ACKS_SERVER = 1ULL << 32,
     ACKS_CLIENT = 1ULL << 63,
};

// NODE INFO
enum N : uint {
     N_ON      =  1U << 0,
     N_NAME    =  1U << 1,
     N_MTU     =  1U << 2,
     N_CONNS_N =  1U << 3,
     N_SECRET  =  1U << 4,
     N_INFO    = (1U << 5) - 1,
};

// A ARRAY DE INPUT É PARA AGUENTAR DEMORA/PERDA DE PACOTES
// A CADA INTERVALO SAO ENVIADOS UM PING POR PATH *ATIVO*
enum I_KEYS : uint {
     I_KEYS_ALL     = 256,
     I_KEYS_DYNAMIC = 253, // NAO TEM QUE CONSIDERAR O OVERFLOW POIS NO KEEPER NAO PRECISA SER ATOMIC
     I_KEY_PING     = 253,
     I_KEY_PONG     = 254, // TEM QUE CABER E PREENCHER O PKT->VERSION
     I_KEY_SYN      = 255,
     I_KEY_MAX      = 255
};

// A ARRAY DE OUTPUT É PARA NAO PRECISAR DE LOCK
enum O_KEYS : uint {
     O_KEYS_ALL     = 11,
     O_KEYS_DYNAMIC =  8, // TEM QUE SER DAR OVERFLOW CONFORME NODE->OCYCLE
     O_KEY_PING     =  8,
     O_KEY_PONG     =  9,
     O_KEY_SYN      = 10,
     O_KEY_MAX      = 10
};

//
enum OPATHS : u64 {
     OPATHS  = 0xFFFFFFFFFFFFFFFFULL,
     OPATH_0 = 0x0001000100010001ULL,
};

enum IPATHS : u16 {
     IPATHS  = 0xFFFFU,
     IPATH_0 = 0x0001U,
};

enum KPATHS : u16 {
     KPATHS  = 0xFFFFU,
     KPATH_0 = 0x0001U,
};

// PATH STATUS/INFO
enum P : u32 {
     P_ON                  =  1U <<  0,
     P_CLIENT              =  1U <<  1,
     P_SERVER              =  1U <<  2,
     P_PHYS                =  1U <<  3,
     P_MAC_SRC             =  1U <<  4,
     P_MAC_DST             =  1U <<  5,
     P_ADDR_SRC            =  1U <<  6,
     P_ADDR_DST            =  1U <<  7,
     P_PORT_SRC            =  1U <<  8,
     P_PORT_DST            =  1U <<  9,
     P_TOS                 =  1U << 10,
     P_TTL                 =  1U << 11,
     P_VPROTO              =  1U << 12,
     P_VID                 =  1U << 13,
     P_RTT_VAR             =  1U << 14,
     P_NAME                =  1U << 15,
     P_DHCP                =  1U << 16,
     P_DHCP_MAC_DST_SERVER =  1U << 17,
     P_DHCP_MAC_DST_GW     =  1U << 18,
     P_EXIST               =  1U << 19,
// TODO: P_INFO_WEIGHT_NODE
// TODO: P_INFO_WEIGHT_ACKS
     P_INFO                = (1U << 20) - 1,
     K_START               =  1U << 20,
     K_SUSPEND             =  1U << 21,
     K_SUSPENDING          =  1U << 22,
     K_LISTEN              =  1U << 23, // TODO: RENAME TO K_DISCOVERING
     K_ESTABLISHED         =  1U << 24, // TODO: RENAME TO K_PINGING
     P_ALL                 = (1U << 25) - 1,

    // P_VPROTO -> NOTE: IT IS THE ETH->PROTO, NOT THE VLAN->PROTO

    // INFORMACOES QUE SAO PERDIDAS AO MUDAR O TIPO DE ENCAPSULAMENTO
    // TODO: P_DHCP ?
    __P_TYPE_CLR = P_MAC_SRC | P_MAC_DST | P_VPROTO | P_VID | P_ADDR_SRC | P_ADDR_DST | P_DHCP,
};

struct path_s {
// 64 -- KEEPER
    u32 info;        // KEEPER (RW)
    u16 weight;      // KEEPER (RO)
    u16 weight_acks; // KEEPER (RO)
    u16 rtt_max;     // KEEPER (RO) -- TODO: REIMPLEMENT THE COMMAND
    u16 rtt;         // KEEPER (RW) / IN (R)
    u16 rtt_var;     // KEEPER (RW) / IN (R) -- CURRENT ONE, BEING REDUCED UNTIL THE CONFIGURED BY USER
    u8 cdown;        // KEEPER (RW)
    u8 oadd;         // KEEPER (RO)
    u64 acks;        // KEEPER (RW) -- HISTORY
    u64 asked;       // KEEPER (RW) -- WHEN I ASKED - PARA MEDIR O RTT
    node_s* node;    // KEEPER_SEND_PINGS
    path_s* next;    // KEEPER_SEND_PINGS -- NA LISTA DE PINGS - ONLY VALID WHEN PATH STATUS >= K_UNSTABLE
    u64 answered;    // KEEPER (R) / IN_PING (W) -- WHEN I RECEIVED ANSWER - PARA PARA MEDIR O RTT E SABER QUE A CONEXÃO ESTÁ VIVA
    u64 pseen[2];    // IN_PING -- LAST PING/PONG->TIME RECEIVED (HIS RAW TIME) - SO WE DON'T ACCEPT REPEATED/GOINGBACKS
    s64 tdiff;       // KEEPER (R) / IN [IF SYN/PING/PONG] (RW) / OUT (R)
    u64 mask;        // KEEPER (R) / KEEPER [ON START] (W) / IN (R) / OUT (R)
    u64 syn;         // KEEPER_SEND_PINGS [IF SYN] (R) / IN [IF SYN] (R) -- O PKT->TIME QUE O CLIENTE VAI USAR, ENQUANTO NAO DESCOBRE ELE
    u64 since;       // KEEPER [ON START] (RW)
// RO -- QUASE NAO USADO
    char name [PATH_NAME_SIZE]; // 24
    u16 sPorts [PATH_PORTS_N]; // 8 EM BIG ENDIAN
    u16 dPorts [PATH_PORTS_N]; // 8
    u8  sPortIndex:4, sPortsN:4;
    u8  dPortIndex:4, dPortsN:4;
    u8  tos;         // KEEPER / IN_DISCOVER
    u8  ttl;         // KEEPER / IN_DISCOVER
    u16 rtt_var_;    // KEEPER (RO) -- CONFIGURED BY USER
    u16 olatency;    // KEEPER (WRITE) / OUT (READ) -- TODO: RETIRAR ISSO
// 112 -- IN READ, OUT READ, IN WRITE (ON RECEIVE PING, WHILE OUT IS DISABLED)
    pkt_s skel;
// 512
    volatile stat_s stats [32];
};

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
    u64* conns; // JIFFIES (60) | PID (4) -- GROUPS OF CONNECTIONS WITH SAME HASH
    u32 connsN; // O OUT PRECISA DISSO  ((((1 << node->order) * PAGE_SIZE) - offsetof(node_s, conns)) / sizeof(conn_s))
    u32 iCycle; // NOTE: O OVERFLOW VAI SER AOS BILHOES
    u8  oCycle; // O OVERFLOW TEM QUE SER MULTIPLO DE O_KEYS_DYNAMIC
    u8  oIndex; // QUAL SERA USADO PARA ENCRIPTAR
    u8  oVersions [O_KEYS_ALL];
    u8 info;
    u16 sdsdsd; //
    u64 aaaaaaa[2];
// 32 -- RO - KEEPER/CMD
    u16 nid;
#ifdef CONFIG_XGW_NMAP
    u16 gw;
#else
    u16 _gw;
#endif
    u32 reserved32;
    node_s** ptr;
    node_s* next;
    net_device_s* dev; // TODO: USA MUITO NO IN, E TALVEZ NO OUT E NO CMD
// 32 -- RO - NAME
    char name [NODE_NAME_SIZE];
// 128 --
    u64 syns [PATHS_N]; // THE DEFAULT ONES
// 14336 -- PATHS
    path_s paths [PATHS_N];
// ---------------------- NODE_SIZE_INIT -----------------------------
// -- KEEPER/OUT READ, IN WRITE
    u64 oKeys [O_KEYS_ALL] [K_LEN];
// -- IN READ, KEEPER WRITE
    u64 iKeys [I_KEYS_ALL] [K_LEN];
// -- RO
    u64 secret [SECRET_KEYS_N] [K_LEN]; // TODO: PARA SER DINAMICO, TERA QUE RESETAR TAMBEM O node->paths[*].pstats
};

//
#define CONNS_SIZE(connsN) ((connsN) * sizeof(u64))

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

//
#define path_is_eth(path)  (path->skel.type & __ETH)
#define path_is_vlan(path) (path->skel.type & __VLAN)
#define path_is_ppp(path)  (path->skel.type & __PPP)
#define path_is_ip4(path)  (path->skel.type & __IP4)
#define path_is_ip6(path)  (path->skel.type & __IP6)
#define path_is_udp(path)  (path->skel.type & __UDP)
#define path_is_tcp(path)  (path->skel.type & __TCP)

#define path_is_udp_tcp(path) (path->skel.type & (__UDP | __TCP))

#define PATH_ID(node, path) ((path) - (node)->paths)

#include "cmd_codes.h"
#include "cmd_errs.h"
#include "cmd_args_types.h"

#define STAT_NAME(a) [a] = #a

static const struct {
    const char* d [DSTATS_N];
    const char* n [NSTATS_N];
    const char* p [PSTATS_N];
} statsStrs = {  // TODO: MARCAR SE ESTIVER ENVIANDO UM PING ATRASADO

    .d = {
        STAT_NAME(DSTATS_I_NOT_XGW),
        STAT_NAME(DSTATS_I_NON_LINEAR),
        STAT_NAME(DSTATS_I_INCOMPLETE),
        STAT_NAME(DSTATS_I_FROM_SELF),
        STAT_NAME(DSTATS_O_DATA_DOWN),
        STAT_NAME(DSTATS_O_DATA_NON_LINEAR),
        STAT_NAME(DSTATS_O_DATA_UNKNOWN),
        STAT_NAME(DSTATS_O_DATA_TO_SELF),
        STAT_NAME(DSTATS_O_DATA_NO_GW),
        STAT_NAME(DSTATS_O_DATA_SIZE_SMALL),
        STAT_NAME(DSTATS_O_DATA_SIZE_BIG),
    },

    .n = {
        STAT_NAME(NSTATS_I_FORWARD),
        STAT_NAME(NSTATS_I_INEXIST),
        STAT_NAME(NSTATS_I_DISABLED),
        STAT_NAME(NSTATS_I_DOWN),
        STAT_NAME(NSTATS_I_PATH_INVALID),
        STAT_NAME(NSTATS_O_DATA_INEXIST),
        STAT_NAME(NSTATS_O_DATA_DISABLED),
        STAT_NAME(NSTATS_O_DATA_MTU_EXCEEDED),
        STAT_NAME(NSTATS_O_DATA_NO_PATH),
    },

    .p = {
        STAT_NAME(PSTATS_I_DATA_GOOD),
        STAT_NAME(PSTATS_I_DATA_IP4_TRUNCATED),
        STAT_NAME(PSTATS_I_DATA_IP6_TRUNCATED),
        STAT_NAME(PSTATS_I_DISABLED),
        STAT_NAME(PSTATS_I_SIZE_SMALL),
        STAT_NAME(PSTATS_I_SIZE_NOT_PING),
        STAT_NAME(PSTATS_I_SIZE_TRUNCATED),
        STAT_NAME(PSTATS_I_HASH_MISMATCH),
        STAT_NAME(PSTATS_I_LISTENING_SYN_TOO_MANY),
        STAT_NAME(PSTATS_I_LISTENING_SYN_WRONG),
        STAT_NAME(PSTATS_I_LISTENING_REFUSE_DATA_AND_PONG),
        STAT_NAME(PSTATS_I_ACCEPTING),
        STAT_NAME(PSTATS_I_CONNECTING_REQUIRE_PONG),
        STAT_NAME(PSTATS_I_ESTABLISHED_REFUSE_SYN),
        STAT_NAME(PSTATS_I_LTIME_MISMATCH_SYN),
        STAT_NAME(PSTATS_I_LTIME_MISMATCH),
        STAT_NAME(PSTATS_I_RTIME_MISMATCH),
        STAT_NAME(PSTATS_I_SYN_ACK_RACED),
        STAT_NAME(PSTATS_I_PING_GOOD),
        STAT_NAME(PSTATS_I_PONG_GOOD),
        STAT_NAME(PSTATS_K_TIMEOUTS),
        STAT_NAME(PSTATS_O_PING_OK),
        STAT_NAME(PSTATS_O_PING_SKB_FAILED),
        STAT_NAME(PSTATS_O_PING_SEND_FAILED),
        STAT_NAME(PSTATS_O_DATA_OK),
        STAT_NAME(PSTATS_O_DATA_NO_HEADROOM),
        STAT_NAME(PSTATS_O_DATA_CKSUM_FAILED),
        STAT_NAME(PSTATS_O_DATA_FAIL),
    }
};

// TODO: NO CASO DO IP4 (RAW) O TRANSPORTE É O PROPRIO XHEADER

// IFRAG BE16 (0b0100000000000000U)

#define SKEL_IP6_FLOW(node, path) (((node)->nid * PATHS_N) + ((path) - (node)->paths))

static const pkt_s models [H_TYPES_N] = {

    [H_TYPE_ETH] = {
        .type     = H_TYPE_ETH,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_s, eth),
        .noffset  = offsetof(pkt_s, x),
        .Noffset  = offsetof(pkt_s, x),
        .toffset  = offsetof(pkt_s, x),
        .protocol = BE16(ETH_P_XGW),
        .encap_eth = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_PPP] = {
        .type     = H_TYPE_ETH_PPP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ppp_s, eth),
        .noffset  = offsetof(encap_eth_ppp_s, ppp),
        .Noffset  = offsetof(encap_eth_ppp_s, ppp),
        .toffset  = offsetof(encap_eth_ppp_s, ppp),
       ._reserved = offsetof(encap_eth_ppp_s, ppp),
        .protocol = BE16(ETH_P_PPP_SES),
        .encap_eth_ppp = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_PPP_SES), // 0x8864
            },
            .ppp = {
                .code    = BE16(0x1100), // VERSION (0x1) | TYPE (0x1) | CODE (0x00)
                .session = BE16(0),
                .size    = BE16(0), // IP SIZE + 2
                .proto   = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_IP4] = {
        .type     = H_TYPE_ETH_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip4_s, eth),
        .noffset  = offsetof(encap_eth_ip4_s, ip4),
        .Noffset  = offsetof(encap_eth_ip4_s, ip4),
        .toffset  = offsetof(pkt_s, x),
        .protocol = BE16(ETH_P_IP),
        .encap_eth_ip4 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_PPP_IP4] = {
        .type     = H_TYPE_ETH_PPP_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ppp_ip4_s, eth),
        .noffset  = offsetof(encap_eth_ppp_ip4_s, ppp),
        .Noffset  = offsetof(encap_eth_ppp_ip4_s, ip4),
        .toffset  = offsetof(pkt_s, x),
       ._reserved = offsetof(encap_eth_ppp_ip4_s, ppp),
        .protocol = BE16(ETH_P_PPP_SES),
        .encap_eth_ppp_ip4 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0021), // ETH_P_IP
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_PPP_IP6] = {
        .type     = H_TYPE_ETH_PPP_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ppp_ip6_s, eth),
        .noffset  = offsetof(encap_eth_ppp_ip6_s, ip6),
        .Noffset  = offsetof(encap_eth_ppp_ip6_s, ip6),
        .toffset  = offsetof(pkt_s, x),
       ._reserved = offsetof(encap_eth_ppp_ip6_s, ppp),
        .protocol = BE16(ETH_P_PPP_SES),
        .encap_eth_ppp_ip6 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0057), // ETH_P_IPV6
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_IP6] = {
        .type     = H_TYPE_ETH_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip6_s, eth),
        .noffset  = offsetof(encap_eth_ip6_s, ip6),
        .Noffset  = offsetof(encap_eth_ip6_s, ip6),
        .toffset  = offsetof(encap_eth_ip6_s, ip6),
        .protocol = BE16(ETH_P_IPV6),
        .encap_eth_ip6 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            }
        }
    },

    [H_TYPE_ETH_IP4_UDP] = {
        .type     = H_TYPE_ETH_IP4_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip4_udp_s, eth),
        .noffset  = offsetof(encap_eth_ip4_udp_s, ip4),
        .Noffset  = offsetof(encap_eth_ip4_udp_s, ip4),
        .toffset  = offsetof(encap_eth_ip4_udp_s, udp),
        .protocol = BE16(ETH_P_IP),
        .encap_eth_ip4_udp = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_UDP),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_ETH_IP6_UDP] = {
        .type     = H_TYPE_ETH_IP6_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_ip6_udp_s, eth),
        .noffset  = offsetof(encap_eth_ip6_udp_s, ip6),
        .Noffset  = offsetof(encap_eth_ip6_udp_s, ip6),
        .toffset  = offsetof(encap_eth_ip6_udp_s, udp),
        .protocol = BE16(ETH_P_IPV6),
        .encap_eth_ip6_udp = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_UDP),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_IP4_UDP] = {
        .type     = H_TYPE_IP4_UDP,
        .msize    = 0,
        .moffset  = offsetof(encap_ip4_udp_s, ip4), // TODO: TEM QUE TER ISSO?
        .noffset  = offsetof(encap_ip4_udp_s, ip4),
        .Noffset  = offsetof(encap_ip4_udp_s, ip4),
        .toffset  = offsetof(encap_ip4_udp_s, udp),
        .protocol = BE16(ETH_P_IP),
        .encap_ip4_udp = {
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_UDP),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_IP6_UDP] = {
        .type     = H_TYPE_IP6_UDP,
        .msize    = 0,
        .moffset  = offsetof(encap_ip6_udp_s, ip6), // TODO: TEM QUE TER ISSO?
        .noffset  = offsetof(encap_ip6_udp_s, ip6),
        .Noffset  = offsetof(encap_ip6_udp_s, ip6),
        .toffset  = offsetof(encap_ip6_udp_s, udp),
        .protocol = BE16(ETH_P_IPV6),
        .encap_ip6_udp = {
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_UDP),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_IP4] = {
        .type     = H_TYPE_IP4,
        .msize    = 0,
        .moffset  = offsetof(encap_eth_ip4_s, ip4),
        .noffset  = offsetof(encap_eth_ip4_s, ip4),
        .Noffset  = offsetof(encap_eth_ip4_s, ip4),
        .toffset  = offsetof(pkt_s, x),
        .protocol = BE16(ETH_P_IP),
        .encap_ip4 = {
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            }
        }
       //encap->i4.ip4.cksum  = ip_fast_csum(&encap->i4.ip4, 5),
    },

#if 0
    [H_TYPE_IP6] = {

    },

#endif

    // TODO: NO CASO DO VLAN, O TRANSPORTE APONTA PARA O VLAN OU PARA O IP?
    [H_TYPE_ETH_VLAN_IP4] = {
        .type     = H_TYPE_ETH_VLAN_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip4_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip4_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip4_s, ip4),
        .toffset  = offsetof(encap_eth_vlan_ip4_s, ip4),
        .protocol = BE16(0),
        .encap_eth_vlan_ip4 = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN_PPP] = {
        .type     = H_TYPE_ETH_VLAN_PPP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ppp_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ppp_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ppp_s, ppp),
        .toffset  = offsetof(encap_eth_vlan_ppp_s, ppp),
       ._reserved = offsetof(encap_eth_vlan_ppp_s, ppp),
        .protocol = BE16(0),
        .encap_eth_vlan_ppp = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_VLAN_PPP_IP4] = {
        .type     = H_TYPE_ETH_VLAN_PPP_IP4,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ppp_ip4_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ppp_ip4_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ppp_ip4_s, ip4),
        .toffset  = offsetof(encap_eth_vlan_ppp_ip4_s, ip4),
       ._reserved = offsetof(encap_eth_vlan_ppp_ip4_s, ppp),
        .protocol = BE16(0),
        .encap_eth_vlan_ppp_ip4 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0021), // ETH_P_IP
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_XGW),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN_PPP_IP6] = {
        .type     = H_TYPE_ETH_VLAN_PPP_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ppp_ip6_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ppp_ip6_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ppp_ip6_s, ip6),
        .toffset  = offsetof(encap_eth_vlan_ppp_ip6_s, ip6),
       ._reserved = offsetof(encap_eth_vlan_ppp_ip6_s, ppp),
        .protocol = BE16(0),
        .encap_eth_vlan_ppp_ip6 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_PPP_SES),
            },
            .ppp = {
                .code    = BE16(0x1100),
                .session = BE16(0),
                .size    = BE16(0),
                .proto   = BE16(0x0057), // ETH_P_IPV6
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN_IP6] = {
        .type     = H_TYPE_ETH_VLAN_IP6,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip6_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip6_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip6_s, ip6),
        .toffset  = offsetof(encap_eth_vlan_ip6_s, ip6),
        .protocol = BE16(0),
        .encap_eth_vlan_ip6 = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_XGW),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
        }
    },

    [H_TYPE_ETH_VLAN] = {
        .type     = H_TYPE_ETH_VLAN,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_s, eth),
        .noffset  = offsetof(encap_eth_vlan_s, vlan), // TODO: PRECISA DISSO?
        .Noffset  = offsetof(encap_eth_vlan_s, vlan),
        .toffset  = offsetof(encap_eth_vlan_s, vlan),
        .protocol = BE16(0), // ETH_P_8021Q / ETH_P_8021AD
        .encap_eth_vlan = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id    = BE16(0),
                .proto = BE16(ETH_P_XGW),
            },
        }
    },

    [H_TYPE_ETH_VLAN_IP4_UDP] = {
        .type     = H_TYPE_ETH_VLAN_IP4_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip4_udp_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip4_udp_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip4_udp_s, ip4),
        .toffset  = offsetof(encap_eth_vlan_ip4_udp_s, udp),
        .protocol = BE16(0),
        .encap_eth_vlan_ip4_udp = {
            .eth = {
                .dmac = { 0, 0, 0, 0, 0, 0 },
                .smac = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IP),
            },
            .ip4 = {
                .version = BE8(0x45),
                .tos     = BE8(0),
                .size    = BE16(0),
                .id      = BE16(0),
                .frag    = BE16(0),
                .ttl     = BE8(0),
                .proto   = BE8(IPPROTO_UDP),
                .cksum   = BE16(0),
                .saddr   = { 0, 0, 0, 0 },
                .daddr   = { 0, 0, 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

    [H_TYPE_ETH_VLAN_IP6_UDP] = {
        .type     = H_TYPE_ETH_VLAN_IP6_UDP,
        .msize    = ETH_HLEN,
        .moffset  = offsetof(encap_eth_vlan_ip6_udp_s, eth),
        .noffset  = offsetof(encap_eth_vlan_ip6_udp_s, vlan),
        .Noffset  = offsetof(encap_eth_vlan_ip6_udp_s, ip6),
        .toffset  = offsetof(encap_eth_vlan_ip6_udp_s, udp),
        .protocol = BE16(0),
        .encap_eth_vlan_ip6_udp = {
            .eth = {
                .dmac  = { 0, 0, 0, 0, 0, 0 },
                .smac  = { 0, 0, 0, 0, 0, 0 },
                .proto = BE16(0),
            },
            .vlan = {
                .id = BE16(0),
                .proto = BE16(ETH_P_IPV6),
            },
            .ip6 = {
                .version = BE8(0x60),
                .tos     = BE8(0),
                .flow    = BE16(0),
                .size    = BE16(0),
                .proto   = BE8(IPPROTO_UDP),
                .ttl     = BE8(0),
                .saddr   = { 0, 0 },
                .daddr   = { 0, 0 },
            },
            .udp = {
                .sport = BE16(0),
                .dport = BE16(0),
                .size  = BE16(0),
                .cksum = BE16(0)
            }
        }
    },

};

DEFINE_SPINLOCK(xlock);

static volatile u64 _xrnd [RANDOM_LEN];
static net_device_s* xgw;
static node_s* knodes;
static u16 nodeSelf;
static volatile u8 gwsN; // TODO: VOLATILE?
static u16 gws [GWS_N]; // TODO: PODE DEIXAR DUAS ARRAYS E MODIFICAR A QUE NAO ESTA SENDO USADA
static node_s* volatile nodes [NODES_N];
#ifdef CONFIG_XGW_NMAP
static volatile u16 nmap [NODES_N];
#endif
static volatile ports_t ports [PORTS_N];
static volatile stat_s dstats           [DSTATS_N];
static volatile stat_s nstats [NODES_N] [NSTATS_N];

// NEED TO BE SEPARATE
//    - SO IT CAN BE USET WITHOUT THE LOCK
//    - SO IT CAN BE USET WITH INTERRUPTS ENABLED
//    - SO IT CAN BE DONE ONCE
//    - SO IT CAN BE DONE PER INTERFACE HASH
static path_s* pings [PING_QUEUES_N];

// USED BY CMD
static inline net_device_s* dev_create_node (const char* const name, const uint nid);

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

static inline u64 get_current_ms (void) {
#ifdef CONFIG_HIGH_RES_TIMERS
    const u64 j = ((RTIME_MIN * NSEC_PER_MSEC) + ktime_get_boottime_ns()) / NSEC_PER_MSEC;
#else // jiffies64_to_msecs()
#error
#endif
    ASSERT(j >= RTIME_MIN);
    ASSERT(j <= RTIME_MAX);
    return j;
}

// X86 RDRAND
#ifdef CONFIG_XGW_RDRAND
static inline u64 rdrand64 (void) {

    u64 r;

    __builtin_ia32_rdrand64_step(&r);

    return r;
}
#endif

// NAO É RANDOM NO SENTIDO DE NAO ADIVINHAVEL, MAS FICA NAO TAO SEQUENCIAL E ALTERANDO DIFERENTES BITS
static inline void random64_n (u64 words[], uint n, u64 seed) {

#ifdef CONFIG_XGW_RDTSC
    seed += __builtin_ia32_rdtsc();
#endif

    for_count (i, n) {
        seed += _xrnd[popcount(seed) % RANDOM_LEN];
        seed += _xrnd[popcount(seed) % RANDOM_LEN] *  seed;
        seed  = _xrnd[popcount(seed) % RANDOM_LEN] += seed;
        words[i] = seed;
    }
}

static inline u64 random64 (u64 seed) {

#ifdef CONFIG_XGW_RDTSC
    seed += __builtin_ia32_rdtsc();
#endif

    seed += _xrnd[popcount(seed) % RANDOM_LEN];
    seed += _xrnd[popcount(seed) % RANDOM_LEN] *  seed;
    seed  = _xrnd[popcount(seed) % RANDOM_LEN] += seed;

    return seed;
}

static inline void random64_refresh (void) {

    // TODO: RDSEED
    u64 seed = __builtin_ia32_rdtsc();

#ifdef CONFIG_XGW_RDRAND
        seed += rdrand64();
#endif

    for_count (i, RANDOM_LEN)
        seed += _xrnd[i] += brot64(seed + _xrnd[i],
                        popcount64(seed ^ _xrnd[i]));
}

static inline void random64_init (void) {

    // TODO: RDSEED
    u64 seed = SUFFIX_ULL(CONFIG_XGW_RANDOM_PING);

#ifdef CONFIG_XGW_RDTSC
    seed += __builtin_ia32_rdtsc();
#endif

    for_count (i, RANDOM_LEN) {
        seed += seed * popcount(seed);
#ifdef CONFIG_XGW_RDRAND
        seed += rdrand64();
#endif // TODO: SWAP64
        _xrnd[i] = seed;
    }
}

static inline uint paged_order (const size_t size) {

    uint real = PAGE_SIZE;

    while (real < size)
           real <<= 1;

    return __ctz(real / PAGE_SIZE);
}

static inline void paged_free (void* const a, const size_t size) {

    free_pages((uintptr_t)a, paged_order(size));
}

static inline void* paged_alloc (const size_t size) {

    return (void*)__get_free_pages(GFP_NOWAIT, paged_order(size));
}

#ifdef CONFIG_XGW_BEEP

enum BEEP_STATUS : uint {
     BEEP_STATUS_SILENT   = 0,
     BEEP_STATUS_DISABLED = 1,
};

BUILD_ASSERT(CONFIG_XGW_BEEP_BASE >= 100);
BUILD_ASSERT(CONFIG_XGW_BEEP_MAX <= 5000);

#if ((CONFIG_XGW_BEEP_BASE >= CONFIG_XGW_BEEP_MAX) && (CONFIG_XGW_BEEP_BASE - CONFIG_XGW_BEEP_MAX) >  1000) \
 || ((CONFIG_XGW_BEEP_BASE <= CONFIG_XGW_BEEP_MAX) && (CONFIG_XGW_BEEP_BASE - CONFIG_XGW_BEEP_MAX) < -1000)
#error    "BAD BEEP BASE/MAX"
#endif

static uint beepStatus = 0;

static void beep_do (uint count) {

    unsigned long flags;

    raw_spin_lock_irqsave(&i8253_lock, flags);

    if (count) {
        count = PIT_TICK_RATE / count;
        /* set command for counter 2, 2 byte write */
        outb_p(0xB6, 0x43);
        /* select desired HZ */
        outb_p(count & 0xff, 0x42);
        outb((count >> 8) & 0xff, 0x42);
        /* enable counter 2 */
        outb_p(inb_p(0x61) | 3, 0x61);
    } else {
        /* disable counter 2 */
        outb(inb_p(0x61) & 0xFC, 0x61);
    }

    raw_spin_unlock_irqrestore(&i8253_lock, flags);
}

static ssize_t __cold_as_ice __optimize_size beep_write (struct file* file, const char __user* ubuf, size_t count, loff_t* ppos) {

    char buff[32];

    if (count == 0)
        return 0;

    if (count >= sizeof(buff))
        return -EFAULT;

    if(copy_from_user(buff,ubuf,count))
        return -EFAULT;

    buff[sizeof(buff) - 1] = 0;

    uint value = 0;

    if (sscanf(buff, "%u", &value) != 1)
        return -EFAULT;

    // O 1 DESATIVA
    if ((beepStatus = value) == 1)
        value = 0;

    beep_do(value);

    return count;
}

static struct proc_ops beepProcOps = {
    .proc_write = beep_write,
};
#endif

static inline u64   swap64 (const u64 x) { return brot64_l(x, popcount64(x)); }
static inline u64 unswap64 (const u64 x) { return brot64_r(x, popcount64(x)); }

// INITIAL KEYS, PER INTERVAL
// TODO: CADA KEY É UMA AVALANCHE DA ANTERIOR
#define CRYPT_LOAD(r) \
    u64 A = K[1] + (K[0] * r), B = K[3] + (K[2] * r), \
        C = K[5] + (K[4] * r), D = K[7] + (K[6] * r)

//
#define CRYPT_ENC(x) (  swap64(  swap64(  swap64((x) + A) + C) + B) + D)
#define CRYPT_DEC(x) (unswap64(unswap64(unswap64((x) - D) - B) - C) - A)
//      CRYPT_ENC(x)  brot64_l(brot64_l((x) + A, popcount(B)) + C, popcount(D))
//      CRYPT_DEC(x) (brot64_r(brot64_r((x), popcount(D)) - C, popcount(B)) - A)

// AVALANCHE OF ORIGINAL THROUGH KEYS
#define CRYPT_ROTATE(x) A += B += C += D += ((A + D) * (B + C)) + x
// 	CRYPT_ROTATE(x) A += B += C += D += ((x + (A * C)) ^ D) + B

// RETURN THE HASH
#define CRYPT_HASH ((A * D) + C) ^ B
//      CRYPT_HASH ((A + D) ^ B) + C

// TODO: CHOOSE THE RIGHT ONE HERE
#define _prefetch_secret __prefetch_r_temporal_low

static inline u64 encrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, const u64 r) {

    ASSERT((end - pos) >= PKT_ALIGN_WORDS);
    ASSERT((end - pos) <= XGW_PAYLOAD_MAX/sizeof(u64));

    CRYPT_LOAD(r);

    do { //__prefetch_w_temporal_high(pos + 2);

        // READ THE ORIGINAL VALUE
        const u64 x = BE64(*pos);

        // WRITE THE ENCRYPTED VALUE
        *pos = BE64(CRYPT_ENC(x));

        CRYPT_ROTATE(x);

    } while (++pos != end);

    return CRYPT_HASH;
}

static inline u64 decrypt (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, const u64 r) {

    ASSERT((end - pos) >= PKT_ALIGN_WORDS);
    ASSERT((end - pos) <= XGW_PAYLOAD_MAX/sizeof(u64));

    CRYPT_LOAD(r);

    do { //__prefetch_w_temporal_high(pos + 2);

        // READ THE ENCRYPTED VALUE AND DECRYPT IT
        const u64 x = CRYPT_DEC(BE64(*pos));

        // WRITE THE ORIGINAL VALUE
        *pos = BE64(x);

        CRYPT_ROTATE(x);

    } while (++pos != end);

    return CRYPT_HASH;
}

//
#define CRYPT_7_INIT \
    u64 A = KEY_7_A, B = KEY_7_B, C = KEY_7_C, D = KEY_7_D, \
        E = KEY_7_E, F = KEY_7_F, G = KEY_7_G, H = KEY_7_H

// TODO: TODOS NO K[*] SAO INICIALIZADOS COM |= (u64)1;
#define CRYPT_7_ROTATE(x) \
    H += G += F += E += D += C += B += A += (F | (u64)1) * x \
    H *= K[0]; G *= K[1]; \
    F *= K[2]; E *= K[3]; \
    D *= K[4]; C *= K[5]; \
    B *= K[6]; A *= K[7]

#define CRYPT_7_ENC(x) \
    --- TODO: !!!!!!!!!!!!!

static inline u64 encrypt_7 (const u64 K[K_LEN], u64* restrict pos, u64* restrict const end, u64 x) {

    ASSERT((end - pos) >= PKT_ALIGN_WORDS);
    ASSERT((end - pos) <= XGW_PAYLOAD_MAX/sizeof(u64));

    CRYPT_7_INIT;

    //__prefetch_w_temporal_high(pos + 2);
    
    loop { 

        CRYPT_7_ROTATE(x);
        
        if (pos == end)
            return CRYPT_HASH_7;
        
        // READ THE ORIGINAL VALUE
        x = BE64(*pos);

        // WRITE THE ENCRYPTED VALUE
        *pos++ = BE64(CRYPT_7_ENC(x));
    }
}

// USING SECRET S, APPLY RANDOM R, AND DERIVE KEY K
static void secret_derivate_random_as_key (const u64 S[SECRET_KEYS_N][K_LEN], const u64 R[K_LEN], u64 K[K_LEN]) {

    u64 x = 0;

    // LOAD DYNAMIC RANDOM AND ITS SUM
    for_count (k, K_LEN) {
        x += K[k] = BE64(R[k]);
    }   x += x >> 32;
        x += x >> 16;

    // CHOOSE AND APPLY SECRET
    const u64* const restrict s = S[x % SECRET_KEYS_N];

    // AS THE TRANSFORMER IS ALL THE RANDOMS ACCUMULATED,
    // THEN EACH WORD IS AFFECTED BY ALL THE OTHERS
    for_count (k, K_LEN)
        // THE TRANSFORMER AFFECTS THE SECRET
        // THE TRANSFORMER CONTINUES BEING AFFECTED BY
        //         RANDOM + (SECRET * TRANSFORMER)
        x += K[k] += s[k] * x;
}

// GENERATE CONSTANT PING/PONG KEYS
// REFAZER ISSO AO ALTERAR:
//  -- SELF ID
//  -- NODE ID
//  -- SECRET (PASSWORD)
// * MUST NOT EXPOSE SECRET.
// * MUST PROVE SENDER/RECEIVER HOST IDS.
// * MUST PROVE THE PING WILL GENERATE THE SAME KEYS.
// * CONSIDERING WE MAY HAVE THOUSANDS OF HOSTS USING THE SAME PASSWORD, MUST NOT BE ABLE TO WATCH ALL AND DISCOVER IT
// --
// WILL GENERATE TWO KEYS:
//      NODE HIGHER WILL USE THEM AS IN/OUT,
//      NODE LOWER WILL USE THEM AS OUT/IN
static void reset_node_ping_keys (node_s* const node, const uint self, const uint peer) {

    ASSERT(self < NODES_N);
    ASSERT(peer < NODES_N);
    ASSERT(self != peer);

    u64* restrict X; u64 sum;
    u64* restrict Y;

    // CADA LADO USA OS MESMOS PING/PONG, POREM INVERTIDOS
    //      SO OS PONTEIROS SAO INVERTIDOS
    //      AS SOMA SIMPLESMENTE É A MESMA (MAIOR | MENOR)
    if (self > peer) {
        sum = 0x0000000100000001ULL * ((self << 16) | peer);
        X = node->iKeys[I_KEY_PING];
        Y = node->oKeys[O_KEY_PING];
    } else {
        sum = 0x0000000100000001ULL * ((peer << 16) | self);
        X = node->oKeys[O_KEY_PING];
        Y = node->iKeys[I_KEY_PING];
    }

    // INITIALIZE THE KEYS
    // MESMO QUE USE O MESMO PASSWORD ENTRE VARIOS NODES, NAO DEIXA QUE O PING KEYS SEJA O MESMO
    for_count (k, 3 * K_LEN) X[k] = sum;
    for_count (k, 3 * K_LEN) Y[k] = sum;
    // TODO: SYN, PING, PONG

    // NOW MERGE WITH THE ENTIRE SECRET
    for_count (s, SECRET_KEYS_N) {
        for_count (k, K_LEN) {
            for_count (k2, 3 * K_LEN) sum += swap64(X[k2] += swap64(node->secret[s][k] + swap64(sum)));
            for_count (k2, 3 * K_LEN) sum += swap64(Y[k2] += swap64(node->secret[s][k] + swap64(sum)));
        }
    }

    // SET THE DEFAULT SYN CODES FOR THE PATHS
    // AN ATTACKER ABLE TO WATCH ONE OF THEM CAN'T KNOW THE OTHER ONES
    for_count (pid, PATHS_N) {
        node->syns[pid] = sum + popcount(sum) * sum;
        sum += swap64(sum);
    }
}

// REPETE ELE ATE PREENCHER TODA A ARRAY
//     -- O DST ESTÁ VAZIO
//     -- O DST AGUENTA TODO O SRC
static inline void copy_and_fill (void* const restrict dst, const uint dst_size, const void* const restrict src, uint src_size) {

    // NO DST TEM ESPACO PARA O SRC INTEIRO
    ASSERT(dst_size >= src_size);

    // COPY THE SRC TO THE DST
    memcpy(dst, src, src_size);

    // RECOPY FROM ITSELF, ITSELF'S SIZE
    uint chunk;

    while ((chunk = dst_size - src_size)) {
        if (chunk > src_size)
            chunk = src_size;
        memcpy(dst + src_size, dst, chunk);
                     src_size += chunk;
    }
}

static void secret_derivate_from_password (u64 S[SECRET_KEYS_N][K_LEN], const u8* const restrict password, const uint size) {

    ASSERT(size >= PASSWORD_SIZE_MIN);
    ASSERT(size <= PASSWORD_SIZE_MAX);
    ASSERT(PASSWORD_SIZE_MAX <= SECRET_SIZE);

    copy_and_fill(S, SECRET_SIZE, password, size);

#ifndef __BIG_ENDIAN
    for_count (s, SECRET_KEYS_N) // EM LOCAL ENDIAN
        for_count (k, K_LEN)
            S[s][k] = BE64(S[s][k]);
#endif

    // INITIALIZE IT WITH THE PASSWORD
    u64 A = S[0][0],
        B = S[0][1],
        C = S[0][2],
        D = S[0][3];

    // NAO DEIXA SER APENAS UMA REPETICAO
    for_count (s, SECRET_KEYS_N)
        for_count (k, K_LEN)
            A += B += C += D += S[s][k] = swap64(swap64(swap64(S[s][k] + D) + C) + B) + A;

    // SHUFFLE
    for_count (c, PASSWORD_ROUNDS) {
        for_count (s, SECRET_KEYS_N) {
            for_count (k, K_LEN) {

                A += S[D % SECRET_KEYS_N][C % K_LEN] * B;
                B += S[C % SECRET_KEYS_N][A % K_LEN] * D;
                C += S[B % SECRET_KEYS_N][D % K_LEN] * A;
                D += S[A % SECRET_KEYS_N][B % K_LEN] * C;

                A += B += C += D += S[s][k] = swap64(swap64(swap64(S[s][k] + D) + C) + B) + A;
            }
        }
    }
}

// AUTHENTICITY AND INTEGRITY
// - SRC HOST ID
// - DST HOST ID
// - PATH ID
// - RECEIVER IN SLOT
// - DATA SIZE
// AUTHENTICITY, INTEGRITY AND PRIVACY
// - DATA

// NOTE: QUALQUER ALTERAÇÃO EM UM BIT DO PATH ID OU DO RCOUNTER TEM QUE RESULTAR EM ALGO DIFERENTE AQUI
#define _PKT_SEED(pkt) BE64(pkt->x.info ^ pkt->x.time)

// A IDÉIA É ASSUMIR QUE O SIZE É SEMPRE MULTIPLO DE 64-BITS.
// DAÍ O RESTO QUE PASSAR DISSO, É "EXPULSO" DO ALIGN, FAZENDO ELE COMECAR MAIS PARA FRENTE.
#define _PKT_START(pkt, size) (PTR(pkt->p) + (size % sizeof(pkt->p[0])))
#define _PKT_END(pkt, size)   (PTR(pkt->p) + PKT_ALIGN_SIZE + size)

// NOTE: TEM QUE FAZER APOS TER SETADO O PKT INFO E RCOUNTER
#define pkt_encrypt(node, o, pkt, size) encrypt(node->oKeys[o], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt))
#define pkt_decrypt(node, i, pkt, size) decrypt(node->iKeys[i], _PKT_START(pkt, size), _PKT_END(pkt, size), _PKT_SEED(pkt))

// NOTE: ASSUME NO IPV4 OPTIONS
// ip: IP PACKET
// size: IP SIZE
static inline u16 tcp_checksum4 (const void* ip, uint size) {

    ASSERT(size >= offsetof(ip4_s, sport));

    uint sum = IPPROTO_TCP + size - IP4_SIZE;

    size -= offsetof(ip4_s, saddr);
    ip   += offsetof(ip4_s, saddr);

    do {
        sum += BE16(*(u16*)ip);
                           ip += sizeof(u16);
    } while ((size -= sizeof(u16))
                   >= sizeof(u16));

    if (size)
        sum += *(u8*)ip << 8;

    sum +=  sum >> 16;
    sum  = ~sum;
    sum &= 0xFFFFU;

    return sum;
}

// NOTE: ASSUME NO IPV6 OPTIONS
static inline u16 tcp_checksum6 (const void* ip, uint size) {

    ASSERT(size >= (IP6_SIZE + TCP_SIZE));
    ASSERT((ip + IP6_SIZE) == &((ip6_s*)ip)->sport);

    uint sum = IPPROTO_TCP + size - IP6_SIZE;

    size -= offsetof(ip6_s, saddr);
    ip   += offsetof(ip6_s, saddr);

    do {
        sum += BE16(*(u16*)ip);
                           ip += sizeof(u16);
    } while ((size -= sizeof(u16))
                   >= sizeof(u16));

    if (size)
        sum += *(u8*)ip << 8;

    sum +=  sum >> 16;
    sum  = ~sum;
    sum &= 0xFFFFU;

    return sum;
}

// TODO:
static inline u16 udp_checksum6 (const void* ip, uint size) {

    return 0;
}

// MUST BE SMALL AND FAST
// TODO: AQUI ENCRIPTA E NAO RETORNA NADA xD
// TODO: SE ESSA PORRA COMPUTAR CHECKSUM TCP/UDP,
// ENTAO VAI TER QUE SER DEPOIS DE ENCRYPTAR
static void pkt_encapsulate (const node_s* const node, const uint o, const u64 rtime, const pkt_s* const skel, skb_s* const skb, void* const restrict orig, const uint orig_size) {

    ASSERT(orig_size >= XGW_PAYLOAD_MIN);
    ASSERT(orig_size <= XGW_PAYLOAD_MAX);

    //ASSERT(atomic_read(&skb->users.refs) == 1);
    ASSERT(!skb_is_nonlinear(skb));

    ASSERT(SKB_HEAD(skb) <=  PTR(orig));
    ASSERT(SKB_END (skb) >= (PTR(orig) + orig_size));

    pkt_s* const pkt = PTR(orig) - (sizeof(pkt_s) + PKT_ALIGN_SIZE);

    // INSERT OUR HEADER
    memcpy(PTR(pkt) + skel->moffset,
          PTR(skel) + skel->moffset,
      sizeof(*skel) - skel->moffset);

    // NOTE: ISSO AQUI SEMPRE É COPIADO POIS ESTA NO HEADER X; OS ENCAPSULAMENTOS SAO DE SIZE DINAMICO
    ASSERT(pkt->phys);
    ASSERT(pkt->moffset >= 0);
    ASSERT(pkt->moffset <= offsetof(pkt_s, x));
    ASSERT(pkt->noffset == (pkt->moffset + pkt->msize));
    ASSERT(pkt->noffset >= pkt->moffset);
    ASSERT(pkt->Noffset >= pkt->noffset);
    ASSERT(pkt->toffset >= pkt->Noffset);
    ASSERT(pkt->toffset <= offsetof(pkt_s, x));

    // NOTE: pkt->[mnt]offset NUNCA PODE COMECAR EM 0 POIS O COMECINHO É O RESERVADO
    // skb_set_mac_header / skb_reset_mac_header
    // skb_set_network_header / skb_reset_network_header
    // SE NAO FOR TER MAC HEADER, ENTAO ESTEMAC_HEADER TEM QUE TERINAR APONTANDO PRO MESMO QUE O DATA
    // OU SEJA, BASTA QUE O PKT->MOFFSET SEJA IGAL AO QUE APONTA PRO INICIO DO ENCAPSULAMENTO
    // NOTE: WE NEED TO SET TAIL ALSO, BECAUSE WE ARE ALSO CREATING PACKETS FOR PING/PONG
    skb->data             =              PTR(pkt) + pkt->moffset;
    skb->mac_header       = _USES_OFFSET(PTR(pkt) + pkt->moffset);
    skb->network_header   = _USES_OFFSET(PTR(pkt) + pkt->noffset); // TODO: TEM QUE SER O VLAN???
    skb->transport_header = _USES_OFFSET(PTR(pkt) + pkt->toffset);
    skb->tail             = _USES_OFFSET(PTR(pkt) + sizeof(*pkt) + PKT_ALIGN_SIZE + orig_size);
    skb->len              =                         sizeof(*pkt) + PKT_ALIGN_SIZE + orig_size - pkt->moffset; // SKB_TAIL(skb) - SKB_DATA(skb) // TODO: COLOCAR ESSE U64 NOS HSIZES DOS MODELS, E RETIRAR DAQUI
    skb->dev       	      = pkt->phys;
    skb->mac_len   	      = pkt->msize;
    skb->protocol         = pkt->protocol;
 // skb->ip_summed        = CHECKSUM_NONE; // NOTE: ISSO AQUI NO PING/PONG

    ASSERT(SKB_MAC      (skb) == (PTR(pkt) + pkt->moffset));
    ASSERT(SKB_NETWORK  (skb) == (PTR(pkt) + pkt->noffset));
    ASSERT(SKB_TRANSPORT(skb) == (PTR(pkt) + pkt->toffset));

    ASSERT(SKB_HEAD(skb) <= SKB_DATA(skb));
    ASSERT(SKB_DATA(skb) <= SKB_TAIL(skb)); // O DATA É UM DESTES: MAC/NETWORK/TRANSPORT/&PKT->X
    ASSERT(SKB_TAIL(skb) <= SKB_END(skb));

    ASSERT((SKB_TAIL(skb) - SKB_DATA(skb)) == skb->len);

    ASSERT(SKB_TAIL(skb) == (PTR(orig) + orig_size));

    //
    random64_n(pkt->p, PKT_ALIGN_WORDS, SUFFIX_ULL(CONFIG_XGW_RANDOM_ENCRYPT_ALIGN));

    // READ BEFORE OVERWRITING IT
    const uint type = pkt->type;

    //
    pkt->x.dsize   = BE16(orig_size);
    pkt->x.version = BE8(node->oVersions[o]);
    pkt->x.time    = BE64(rtime);
    pkt->x.hash    = BE64(pkt_encrypt(node, o, pkt, orig_size));

    ASSERT(pkt->x.src  == BE16(nodeSelf));
    ASSERT(pkt->x.dst  == BE16(node->nid));

    switch (type) {

        case H_TYPE_ETH_PPP_IP4:
        case H_TYPE_ETH_VLAN_PPP_IP4:

            pkt->encap_eth_ppp_ip4.ppp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + sizeof(hdr_ip4_s) + sizeof(u16));

            fallthrough;
        case H_TYPE_IP4:
        case H_TYPE_ETH_IP4:
        case H_TYPE_ETH_VLAN_IP4:

     ASSERT(pkt->encap_eth_ppp_ip4.ip4.cksum == 0);
            pkt->encap_eth_ppp_ip4.ip4.size  = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + sizeof(hdr_ip4_s));
            pkt->encap_eth_ppp_ip4.ip4.cksum = ip_fast_csum(&pkt->encap_ip4.ip4, 5);

            break;

        case H_TYPE_ETH_PPP_IP6:
        case H_TYPE_ETH_VLAN_PPP_IP6:

            pkt->encap_eth_ppp_ip6.ppp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + sizeof(hdr_ip6_s) + sizeof(u16));

            fallthrough;
        case H_TYPE_IP6:
        case H_TYPE_ETH_IP6:
        case H_TYPE_ETH_VLAN_IP6:

            pkt->encap_eth_ppp_ip6.ip6.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size);

            break;

        case H_TYPE_IP4_UDP:
        case H_TYPE_ETH_IP4_UDP:
        case H_TYPE_ETH_VLAN_IP4_UDP:

     ASSERT(pkt->encap_ip4_udp.udp.cksum == 0);
     ASSERT(pkt->encap_ip4_udp.ip4.cksum == 0);
            pkt->encap_ip4_udp.udp.size  = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + sizeof(hdr_udp_s));
            pkt->encap_ip4_udp.ip4.size  = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + sizeof(hdr_udp_s) + sizeof(hdr_ip4_s));
            pkt->encap_ip4_udp.ip4.cksum = ip_fast_csum(&pkt->encap_ip4_udp.ip4, 5);

            break;

        case H_TYPE_IP6_UDP:
        case H_TYPE_ETH_IP6_UDP: // TODO: O IPV6 OBRIGA UDP CHECKSUM. ESTA DEIXANDO O ZERO AQUI, MAS DEVERA COMPUTAR DEPOIS
        case H_TYPE_ETH_VLAN_IP6_UDP:

     ASSERT(pkt->encap_ip6_udp.udp.cksum == 0);
            pkt->encap_ip6_udp.udp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + sizeof(hdr_udp_s));
            pkt->encap_ip6_udp.ip6.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + sizeof(hdr_udp_s));

            break;

        case H_TYPE_ETH_PPP:
        case H_TYPE_ETH_VLAN_PPP:

            pkt->encap_eth_ppp.ppp.size = BE16(PKT_X_SIZE + PKT_ALIGN_SIZE + orig_size + 2);

            break;

        case H_TYPE_IP4_TCP:
        case H_TYPE_ETH_IP4_TCP:
        case H_TYPE_ETH_VLAN_IP4_TCP:

            break;

        case H_TYPE_IP6_TCP:
        case H_TYPE_ETH_IP6_TCP:
        case H_TYPE_ETH_VLAN_IP6_TCP:

            break;

        case H_TYPE_RAW:
        case H_TYPE_ETH:
        case H_TYPE_ETH_VLAN:
            //
            break;
    }
}

static netdev_tx_t out (skb_s* const skb, net_device_s* const dev) {

    // NOTE: THIS SIZE MAY BE WRONG, AS WE DIDNT LINEARIZE IT YET
    uint stat; volatile stat_s* _stat;

    if (skb_is_nonlinear(skb))
        ret_dev(DSTATS_O_DATA_NON_LINEAR);

    const size_t orig_size = skb->len;

    if (orig_size < XGW_PAYLOAD_MIN)
        ret_dev(DSTATS_O_DATA_SIZE_SMALL);

    if (orig_size > XGW_PAYLOAD_MAX)
        ret_dev(DSTATS_O_DATA_SIZE_BIG);

#ifdef CONFIG_XGW_GATEWAY_TCP_PROXY
    switch (skb->mark & 0xFFFF0000U) { // TODO: TEM QUE IMPEDIR DE SETAR MANUALMENTE ESTES MARKS NO SETSOCKOPT, IPTABLES ETC

        case XGW_TCP_PROXY_MARK_4: {

            ASSERT(skb->protocol == BE16(ETH_P_IP));

            ip4_s* const ip = SKB_NETWORK(skb);

            ASSERT(ip->proto == BE8(IPPROTO_TCP));

            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            ip->sport  = BE16(skb->mark & 0xFFFFU);

        } break;

        case XGW_TCP_PROXY_MARK_6: {

            // TODO:
            ASSERT(skb->protocol == BE16(ETH_P_IPV6));

            ip6_s* const ip = SKB_NETWORK(skb);

            ASSERT(ip->proto == BE8(IPPROTO_TCP));

            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            ip->sport  = BE16(skb->mark & 0xFFFFU);

        } break;
    }
#endif

    // THE PAYLOAD (THIS WILL POINT TO THE NETWORK HEADER)
    u64* const orig = SKB_NETWORK(skb);
    ASSERT(PTR(orig) == SKB_DATA(skb));

    ASSERT(SKB_HEAD(skb) <=  PTR(orig));
    ASSERT(SKB_TAIL(skb) == (PTR(orig) + orig_size));
    ASSERT(SKB_END (skb) >= (PTR(orig) + orig_size));

    ASSERT(SKB_HEAD(skb) <= SKB_DATA(skb));
    ASSERT(SKB_DATA(skb) <= SKB_TAIL(skb));
    ASSERT(SKB_TAIL(skb) <= SKB_END(skb));

    // WILL GET DESTINATION NODE AND HASH THE PATH
    u64 nid, cid;

    // NOTE: ASSUMINDO QUE O SKB->LEN TEM AO MENOS ESTES CABECALHOS
    // NOTE: ASSUMINDO QUE NAO TEM IPV4/IPV6 OPTIONS
    // NOTE: SE ATRAPALHA COM ICMP
    if ((cid = BE64(orig[0]) >> 56) == 0x45) { ASSERT(skb->protocol == BE16(ETH_P_IP));
        // IPV4 (NOTE: ASSUMING NO IP OPTION/FRAGMENTATION)
        // PROTO, SADDR, DADDR SPORT DPORT
        cid = (orig[1] & BE64(0x00FF0000FFFFFFFFULL)) + orig[2];
        // DEIXA SO O PREFIXO E O NODE
        // THIS 32 IS BECAUSE WE HAVE ALSO READ THE PORTS
        nid = ((BE64(orig[2]) >> 32) ^ V4_PREFIX) >> (32 - V4_WIDTH_PREFIX - V4_WIDTH_NODE);
        // OS BITS DA REDE QUE DIFERIREM DARAO 1, FAZENDO COM QUE O HID SEJA GRANDE
        // OS BITS DO NODE DARAO OS MESMOS
    } elif ((cid >> 4) == 0x6) { ASSERT(skb->protocol == BE16(ETH_P_IPV6));
        // IPV6 (NOTE: ASSUMING NO IP NEXT HEADER/FRAGMENTATION)
        // FLOW, PROTO, SADDR, DADDR
        cid = (orig[0] & BE64(0x000FFFFF0000FF00ULL)) + orig[1] + orig[2] + orig[3] + orig[4];
        nid = (BE64(orig[3]) ^ V6_PREFIX) >> (64 - V6_WIDTH_PREFIX - V6_WIDTH_NODE);
    } else
        // UNSUPORTED
        ret_dev(DSTATS_O_DATA_UNKNOWN);

    // TODO: CRIAR O XGW COMNETDEV priv?
    if (dev == xgw) {
        // IF ITS THROUGHT THE GLOBAL INTERFACE, WE MUST IDENTIFY THE DESTINATION NODE BY THE DESTINATION ADDRESS
        if (nid >= NODES_N) {
            // DESTINATION IS NOT A NODE
            // NODE IS ONE OF THE GATEWAYS
            if (gwsN == 0)
                ret_dev(DSTATS_O_DATA_NO_GW);
            nid = gws[popcount(cid) % gwsN];
        }
    } else
        // WHATEVER THE DESTINATION IS, IT IS TUNNELED TO A SPECIFIC NODE BY IT'S INTERFACE
        // TODO: UM FILTRO EM OUTRAS COISAS PARA NAO DEIXAR PASSAR PARA ENDERECOS XGW EM OUTRAS INTERFACES
        // TODO: UM FILTRO EM OUTRAS COISAS PARA NAO DEIXAR PASSAR PARA MARCAS XGW EM OUTRAS INTERFACES
        // IN THIS CASE THE NID READEN FROM THE ADDRESSES IS USELESS; AS WE CAN ROUTE TO A NODE THROUGHT ANODER ONE
        nid = *(uint*)netdev_priv(dev); // TODO: JUMTO COM AQUELE IFFLAGS??

    ASSERT(nid < NODES_N);

    //
#ifdef CONFIG_XGW_NMAP
    nid = nmap[nid];
#endif

    ASSERT(nid < NODES_N);

    if (nid == nodeSelf)
        // CANNOT SEND TO ITSELF
        ret_dev(DSTATS_O_DATA_TO_SELF);

    // TODO: CONTINUAR RECEBENDO PACOTES DE CONTROLE/PING/PONG MESMO COM A INTERFACE DESATIVADA
    //        DAI SERA INTERESSANTE UMA FLAG GLOBAL XGW ON / OFF, NO MESMO ESQUEMA QUE O NODE->ON & PATH->ON

    // IDENTIFIED THE NODE
    // TODO: IF THE NODE IS NOT AVAILABLE, SEND IT TO ANOTHER ONE
    //     -- WILL NEED TO REPORT THE NODES WE CAN REACH IN THE PING, WITH A BIT MAP: 1024*8 = 8192 NODES
    //     -- WILL NEED SOME KIND OF TTL -> junto com o xPath, o xTTL
    //            e ai se o xttl for != 0, intepreta, desconta um, e manda ele (nao vai poder desencriptar)
    node_s* const node = nodes_get_unlocked(nid);

    if (node == NULL)
        ret_node(NSTATS_O_DATA_INEXIST);

    if (node_is_off(node))
        ret_node(NSTATS_O_DATA_DISABLED);

    if (node->mtu < orig_size)
        ret_node(NSTATS_O_DATA_MTU_EXCEEDED);

    const u64 opaths = atomic_get(&node->opaths);

    if (!opaths)
        ret_node(NSTATS_O_DATA_NO_PATH);

    // CHOOSE CONN
    cid += cid >> 32;
    cid += cid >> 16;
    cid %= node->connsN;

    u64* const conn = &node->conns[cid];

    const u64 _now = get_current_ms();

    ASSERT(_now >= RTIME_MIN);
    ASSERT(_now <= RTIME_MAX);

    // LOAD STREAM TIMEOUT + PID
    const u64 burst = atomic_get(conn);

    // CHOOSE A PATH
    // STARTING FROM CURRENT, BUT CHANGE IF IDLE
    const uint pid0 = (burst + ((burst >> 5) < _now)) % PATHS_N;
    // NOTE: NO CASO DE OPATHS SER 0, ESTE VALOR FINAL SERIA UNSPECIFIED
    // NOTE: O ULTIMO GRUPO TEM QUE SER REPETIDO
    const uint pid = __ctz((opaths >> pid0) << pid0) % PATHS_N;

    ASSERT(opaths & OPATH(pid));

    path_s* const path = &node->paths[pid];

    // STORE STREAM TIMEOUT + PID
    // CONSIDERAR O TEMPO DE IDA + CPU BUSY TIME + IMPRECISOES
    atomic_set(conn, ((_now + (atomic_get(&path->rtt) * 3) / 4) << 5) | pid); // olatency

#if 1
    if (skb->ip_summed == CHECKSUM_PARTIAL)
        if (skb_checksum_help(skb))
            ret_path(PSTATS_O_DATA_CKSUM_FAILED);
#endif

    // NOTE: THIS STAT WILL ONLY HAPPEN ON DATA, NOT ON PING/PONG
    if ((PTR(orig) - (sizeof(pkt_s) + PKT_ALIGN_SIZE) + path->skel.moffset) < SKB_HEAD(skb)) // path->skel.hsize + PKT_ALIGN_SIZE
        // TODO: SE TIVER ESPACO NO FIM, DAR UM MEMMOVE()
        ret_path(PSTATS_O_DATA_NO_HEADROOM);

    pkt_encapsulate(node, atomic_get(&node->oIndex), RTIME(path->mask + _now, atomic_get(&path->tdiff)), &path->skel, skb, orig, orig_size);

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    dev_queue_xmit(skb);
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED

    stat = PSTATS_O_DATA_OK;

_ret_path: _stat = path->stats; goto _ret;
_ret_node: _stat = nstats[nid]; goto _ret;
_ret_dev:  _stat = dstats;
_ret:

    stat_inc_count(&_stat[stat].count);
    stat_inc_bytes(&_stat[stat].bytes, skb->len);

    if (stat != PSTATS_O_DATA_OK)
        dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static inline void ping_receive (node_s* const node, const ping_s* const ping) {

    u64 K[K_LEN];

    // LEARN HIS INPUT KEYS (MY OUTPUT KEYS)
    const uint ver = BE8(ping->ver);

    ASSERT(ver < I_KEYS_DYNAMIC);

    secret_derivate_random_as_key(node->secret, ping->rnd, K);

    // FAZ ISSO PRIMEIRO ANTES DE LIBERAR O PATH PARA ENVIAR
    const uint o = __atomic_add_fetch(&node->oCycle, 1, __ATOMIC_ACQUIRE) % O_KEYS_DYNAMIC;
                                       node->oVersions[o] = ver;
                                memcpy(node->oKeys[o], K, sizeof(K));
                     __atomic_store_n(&node->oIndex, o,  __ATOMIC_RELEASE);
}

static void ping_send (node_s* const node, path_s* const path, const pkt_s* const skel, const u64 now, const u64 rtime, const uint o) {

    uint stat;

    skb_s* const skb = alloc_skb(96 + PKT_SIZE + PKT_ALIGN_SIZE + PING_SIZE + 96, GFP_ATOMIC);

    if (skb) {

        ASSERT(skb->len == 0);
        ASSERT(SKB_DATA(skb) == SKB_HEAD(skb));
        ASSERT(SKB_DATA(skb) == SKB_TAIL(skb));
        ASSERT(SKB_END(skb)  > (SKB_TAIL(skb) + 96 + PKT_SIZE + PKT_ALIGN_SIZE + PING_SIZE + 96));

        // TODO: USA O SKB_DATA ALIGNED
        ping_s* const ping = SKB_DATA(skb) + 96 + PKT_SIZE + PKT_ALIGN_SIZE;

        // GERA AS KEYS
        random64_n(PTR(ping), PING_RANDOMS_N, SUFFIX_ULL(CONFIG_XGW_RANDOM_PING));

        ping->time = BE64(now);

        if (o != O_KEY_SYN) {

            // A CADA PING/PONG O SLOT MAIS ANTIGO É RECICLADO.
            // ENTÃO AS KEYS MAIS ANTIGAS SÃO AUTOMATICAMENTE DESCARTADAS.
            // OVERFLOWS SERAO PROBLEMAS, ENTAO TEM QUE USAR PALAVRA GRANDE.
            const uint i = __atomic_add_fetch(&node->iCycle, 1, __ATOMIC_RELAXED) % I_KEYS_DYNAMIC;

            ping->ver = BE8(i); // OVERWRITE WITH THE VERSION

            // SEM ATOMICITY/BARRIER POIS ESTA USANDO UMA KEY JA EXPIRADA
            secret_derivate_random_as_key(node->secret, ping->rnd, node->iKeys[i]);
        }

        pkt_encapsulate(node, o, rtime, skel, skb, ping, PING_SIZE);

        skb->ip_summed = CHECKSUM_NONE;

        if (dev_queue_xmit(skb))
            // FAILED TO SEND THE SKB
            // NOTE: THE SKB WAS ALREADY CONSUMED
            stat = PSTATS_O_PING_SEND_FAILED;
        else
            stat = PSTATS_O_PING_OK;
    } else // FAILED TO ALLOCATE SKB
        stat = PSTATS_O_PING_SKB_FAILED;

    stat_inc_bytes(&path->stats[stat].bytes, PING_SIZE);
    stat_inc_count(&path->stats[stat].count);
}

// ASSERT: IPPROTO_UDP != PPP_PROTO_IP4
// ASSERT: IPPROTO_UDP != PPP_PROTO_IP6
BUILD_ASSERT(IPPROTO_UDP != ETH_P_IP);
BUILD_ASSERT(IPPROTO_UDP != ETH_P_IPV6);

// ASSERT: IPPROTO_TCP != PPP_PROTO_IP4
// ASSERT: IPPROTO_TCP != PPP_PROTO_IP6
BUILD_ASSERT(IPPROTO_TCP != ETH_P_IP);
BUILD_ASSERT(IPPROTO_TCP != ETH_P_IPV6);

static inline void in_discover (const path_s* const path, const skb_s* const skb, pkt_s* const skel) {

    const void* orig = SKB_NETWORK(skb);

    // POR SEGURANCA VAMOS EXIGIR ETH_HLEN
    // É MELHOR FICAR SEM HARDWARE HEADER DO QUE PROBLEMAS MAIORES
    uint T = (skb->mac_len == ETH_HLEN) * __ETH;

    uint proto = skb->protocol;

    switch (proto) {
        case BE16(ETH_P_8021Q):
        case BE16(ETH_P_8021AD): // NOTE: PODE ACABAR VIRANDO __VLAN SEM __ETH
            T |= __VLAN;
            proto =      ((hdr_vlan_s*)orig)->proto;
            orig += sizeof(hdr_vlan_s);
            break;
    }

    switch (proto) {
        case BE16(ETH_P_PPP_SES):
            T |= __PPP;
            proto =      ((hdr_ppp_s*)orig)->proto;
            orig += sizeof(hdr_ppp_s);
            break;
    }

    switch (proto) {
        case BE16(PPP_PROTO_IP4):
        case BE16(ETH_P_IP):
            T |= __IP4;
            proto =      ((hdr_ip4_s*)orig)->proto;
            orig += sizeof(hdr_ip4_s);
            break;
        case BE16(PPP_PROTO_IP6):
        case BE16(ETH_P_IPV6):
            T |= __IP6;
            proto =      ((hdr_ip6_s*)orig)->proto;
            orig += sizeof(hdr_ip6_s);
            break;
    }

    switch (proto) {
        case BE8(IPPROTO_UDP):
            T |= __UDP;
            orig += sizeof(hdr_udp_s);
            break;
        case BE8(IPPROTO_TCP):
            T |= __TCP;
            orig += sizeof(hdr_tcp_s);
            break;
    }

    //
    orig -= offsetof(pkt_s, x);

    memcpy(skel, &models[T], sizeof(pkt_s));

    // THE SKEL MUST MATCH THIS PACKET TYPE
    ASSERT(skel->type == T);

    if (T & __ETH) {
        memcpy(PTR(skel) + skel->moffset + 6, orig + skel->moffset + 0, 6); // DST MAC -> SRC MAC
        memcpy(PTR(skel) + skel->moffset + 0, orig + skel->moffset + 6, 6); // SRC MAC -> DST MAC
    }

    if (T & __VLAN)
        memcpy(PTR(skel) + skel->moffset + 12, orig + skel->moffset + 12, 4); // VPROTO E VID

    if (T & __PPP)
        // COPIA O CODE, SESSION, SIZE E PROTOCOL
        // O SIZE OVERWRITED DEPOIS
        memcpy(PTR(skel) + skel->_reserved, orig + skel->_reserved, 8);

    if (T & __IP4) {
        memcpy(PTR(skel) + skel->Noffset + 16, orig + skel->Noffset + 12, 4); // DST ADDR -> SRC ADDR
        memcpy(PTR(skel) + skel->Noffset + 12, orig + skel->Noffset + 16, 4); // SRC ADDR -> DST ADDR
    } elif (T & __IP6) {
        memcpy(PTR(skel) + skel->Noffset + 24, orig + skel->Noffset +  8, 16); // DST ADDR -> SRC ADDR
        memcpy(PTR(skel) + skel->Noffset +  8, orig + skel->Noffset + 24, 16); // SRC ADDR -> DST ADDR
    }

    if (T & (__UDP | __TCP)) {
        memcpy(PTR(skel) + skel->toffset + 0, orig + skel->toffset + 2, 2); // DST PORT -> SRC PORT
        memcpy(PTR(skel) + skel->toffset + 2, orig + skel->toffset + 0, 2); // SRC PORT -> DST PORT
    }

    // TEM QUE FAZER ISSO AQUI
    skel->x.dst  = ((pkt_s*)orig)->x.src;
    skel->x.src  = ((pkt_s*)orig)->x.dst;
    skel->x.path = ((pkt_s*)orig)->x.path;
 // skel->x.version --> ON encrypt()
 // skel->x.dsize   --> ON encrypt()
 // skel->x.seed    --> ON encrypt()
 // skel->x.hash    --> ON encrypt()

    // PRECISA DISSO POIS SE FOR VLAN AI DIFERE
    skel->protocol = skb->protocol;
    skel->phys     = skb->dev;

    // SET TOS/TTL FROM PATH
    if (T & __IP4) {
        hdr_ip4_s* const ip4 = PKT_IP4(skel);
                         ip4->tos = BE8(path->tos);
                         ip4->ttl = BE8(path->ttl);
    } elif (T & __IP6) {
        hdr_ip6_s* const ip6 = PKT_IP6(skel);
                         ip6->tos = BE8(path->tos);
                         ip6->ttl = BE8(path->ttl);
                         ip6->flow = BE16(SKEL_IP6_FLOW(path->node, path));
    }
}

// IT MUST BE NOT INLINED, AS THE WHOLE INTENTION OF SEPARATING IT AS A FUNCTION IS TO MINIMIZE THE IN FUNCTION
// WE DARE TO REDO SOME THINGS HERE, SO IF WE INLINE, THOSE WILL BE SURPLEFUOUS.
static noinline uint in_ping (node_s* const node, const skb_s* const skb, pkt_s* const pkt) {

    pkt_s* skel; pkt_s temp_skel;

    const ping_s* const ping = PKT_DATA(pkt);

    const uint pid  = BE8(pkt->x.path);
    const uint i    = BE8(pkt->x.version);
    const u64 ltime = BE64(pkt->x.time);
    const u64 rtime = BE64(ping->time);

    ASSERT(pid <= PID_MAX);
    ASSERT(i == I_KEY_PING
        || i == I_KEY_PONG
        || i == I_KEY_SYN);
    ASSERT(rtime >= PTIME_MIN);
    ASSERT(rtime <= PTIME_MAX);

    path_s* const path = &node->paths[pid];

    const u64 now = path->mask + get_current_ms();

    ASSERT(now >= PTIME_MIN);
    ASSERT(now <= PTIME_MAX);

    s64 tdiff;

    if (i == I_KEY_SYN) {

        ASSERT(ltime == path->syn);

        // ESTE RTIME NÃO CONSIDERA O ATRASO
        tdiff = LTIME_DIFF_RTIME(now, rtime);

        ASSERT(tdiff >= TDIFF_MIN);
        ASSERT(tdiff <= TDIFF_MAX);

    } else {

        ASSERT(ltime >= PTIME_MIN);
        ASSERT(ltime <= PTIME_MAX);

        // HIS RAW TIME MUST ADVANCE
        // SEPARATE PING AND PONG
        volatile u64* const ptr = &path->pseen[i == I_KEY_PONG];

        u64 seen = atomic_get(ptr);

        ASSERT((seen >= PTIME_MIN &&
                seen <= PTIME_MAX) ||
                seen == 0);

        // CONSIDERA QUE PODE TER PERDIDO ALGUNS PINGS
        if (seen && (rtime - seen) > 49152)
            // BACKWARD / REPEATED / BIG JUMP
            return PSTATS_I_RTIME_MISMATCH;

        if (!__atomic_compare_exchange_n(ptr, &seen, rtime + 1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            // RACE CONDITION
            return PSTATS_I_RTIME_MISMATCH;

        // TODO: USAR UM VALOR QUE NAO SEJA 0 PARA TDIFFS NAO INICIALIZADOS
        tdiff = __atomic_load_n(&path->tdiff, __ATOMIC_RELAXED);

        ASSERT(tdiff >= TDIFF_MIN);
        ASSERT(tdiff <= TDIFF_MAX);

        tdiff = (
            // CONSIDERA O MEU
            tdiff * (tdiff != 0) +
            // SE NIVELA AO PEER
            // O SYN USA O CODIGO, E O PONG DE UM SYN NAO CONSIDERA O LATENCY; ENTAO SO PODE CONSIDERAR ESTA RELACAO DE UM PING
            LTIME_DIFF_RTIME(ltime, rtime) * (i == I_KEY_PING) +
            // NOTE: CUIDADO COM ESTE LAG AQUI, POIS TALVEZ NAO FOI DESCOBERTO O REAL
            // NOTE: O KEEPER INICIA O PATH->RTT COM UM PATH->RTT_INITIAL
            LTIME_DIFF_RTIME(now, rtime + atomic_get(&path->rtt)/2)
        ) / ((tdiff != 0) + (i == I_KEY_PING) + 1);

        ASSERT(tdiff >= TDIFF_MIN);
        ASSERT(tdiff <= TDIFF_MAX);

        //
        __atomic_store_n(&path->tdiff, tdiff, __ATOMIC_SEQ_CST);

        //
        ping_receive(node, ping);

        if (i == I_KEY_PONG) {
            // CONNECTING -> ESTABLISHED
            __atomic_store_n(&path->answered, now, __ATOMIC_SEQ_CST);
            return PSTATS_I_PONG_GOOD;
        }
    }

    u64 answered = __atomic_load_n(&path->answered, __ATOMIC_SEQ_CST);

    if (answered >= PTIME_MIN) {
        // IF I AM A CLIENT, I ALREADY RECEIVED A PONG
        // IF I AM A SERVER, I ALREADY RECEIVED A SYN AND A SYN-ACK

        // USE THE KNOWN PATH
        skel = &path->skel;

    } elif (answered == ANSWERED_LISTENING) {

        if (i == I_KEY_SYN) {
            // LEARN O PATH NA STACK
            skel = &temp_skel;
        } else { // SYN-ACK
            if (!__atomic_compare_exchange_n(&path->answered, &answered, ANSWERED_ACCEPTING, 0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
                // COULD NOT LOCK THE PATH
                return PSTATS_I_SYN_ACK_RACED;
            // LEARN O PATH NO PATH
            skel = &path->skel;
        }

        in_discover(path, skb, skel);

        if (skel == &path->skel)
            // UNLOCK PATH
            __atomic_store_n(&path->answered, now, __ATOMIC_SEQ_CST);

    } else
        // STILL ACCEPTING
        return PSTATS_I_SYN_ACK_RACED;

    // RESPONDE COM UM PONG
    ping_send(node, path, skel, now, RTIME(now, tdiff), O_KEY_PONG);

    return PSTATS_I_PING_GOOD;
}

// TODO: FIXME: PROTECT THE REAL SERVER TCP PORTS SO WE DON'T NEED TO BIND TO THE FAKE INTERFACE
int in (skb_s* const skb) {

    uint stat; volatile stat_s* _stat;

    if (skb_linearize(skb))
        ret_dev(DSTATS_I_NON_LINEAR);

    const void* hdr;

    void*       ptr = SKB_NETWORK(skb);
    void* const end = SKB_TAIL(skb);

    //
    uint proto = skb->protocol;

    // NOTE: FICAR DE OLHO NO QUE O skb_vlan_untag() FAZ
    switch (proto) {
        case BE16(ETH_P_8021Q):
        case BE16(ETH_P_8021AD): {
            const hdr_vlan_s* const vlan = ptr;
            if ((ptr += sizeof(*vlan)) > end)
                ret_dev(DSTATS_I_INCOMPLETE);
            proto = vlan->proto;
        } break;
    }

    switch (proto) {

        case BE16(ETH_P_PPP_SES): {
            const hdr_ppp_s* const ppp = ptr;
            if ((ptr += sizeof(*ppp)) > end)
                ret_dev(DSTATS_I_INCOMPLETE);
            switch (ppp->proto) {
                case BE16(PPP_PROTO_IP4):
                    hdr = ptr + offsetof(hdr_ip4_s, proto);
                    proto =       sizeof(hdr_ip4_s);
                    break;
                case BE16(PPP_PROTO_IP6):
                    hdr = ptr + offsetof(hdr_ip6_s, proto);
                    proto =       sizeof(hdr_ip6_s);
                    break;
                case BE16(PPP_PROTO_XGW):
                    goto _is_xgw;
                default:
                    goto _not_xgw;
            }
        } break;

        case BE16(ETH_P_IP):
            hdr = ptr + offsetof(hdr_ip4_s, proto);
            proto =       sizeof(hdr_ip4_s);
            break;
        case BE16(ETH_P_IPV6):
            hdr = ptr + offsetof(hdr_ip6_s, proto);
            proto =       sizeof(hdr_ip6_s);
            break;
        case BE16(ETH_P_XGW):
            goto _is_xgw;
        default:
            goto _not_xgw;
    }

    // PTR POINTS TO IP
    // HDR POINTS TO IP PROTOCOL
    // PROTO IS IP SIZE

    if ((ptr += proto) > end)
        ret_dev(DSTATS_I_INCOMPLETE);

    proto = *(u8*)hdr;

    switch (proto) {
        case BE8(IPPROTO_UDP):
            proto = sizeof(hdr_udp_s);
            break;
        case BE8(IPPROTO_TCP):
            proto = sizeof(hdr_tcp_s);
            break;
        case BE8(IPPROTO_XGW):
            goto _is_xgw;
        default:
            goto _not_xgw;
    }

    // PTR POINTS TO TRANSPORT
    // PROTO IS TRANSPORT SIZE

    hdr = ptr;

    if ((ptr += proto) > end)
        ret_dev(DSTATS_I_INCOMPLETE);

    if (!ports_is_enabled(BE16(((u16*)hdr)[1])))
        goto _not_xgw;

_is_xgw:

    // AGORA SABE ONDE COMECA O PKT
    pkt_s* const pkt = (ptr + sizeof(hdr_x_s)) - sizeof(pkt_s);

    if (PKT_DATA(pkt) > end)
        // MISSING HEADER + ALIGN
        ret_dev(DSTATS_I_INCOMPLETE);

    const uint nid    = BE16 (pkt->x.src);
    const uint dst    = BE16 (pkt->x.dst);
    const uint pid    = BE8  (pkt->x.path);
    const uint i      = BE8  (pkt->x.version);
    const uint size   = BE16 (pkt->x.dsize);
    const u64  ltime  = BE64 (pkt->x.time);
    const u64  hash   = BE64 (pkt->x.hash);

    if (nid == nodeSelf)
        ret_dev(DSTATS_I_FROM_SELF);

    if (dst != nodeSelf)
        ret_node(NSTATS_I_FORWARD);

    // TODO: UMA FLAG GLOBAL XGW IS DISABLED
    // TODO: UMA STAT GLOBAL XGW IN IS DISABLED
    // TODO: UMA STAT GLOBAL XGW OUT IS DISABLED

    node_s* const node = nodes_get_unlocked(nid);

    if (node == NULL)
        ret_node(NSTATS_I_INEXIST);

    if (node_is_off(node))
        ret_node(NSTATS_I_DISABLED);

    if (!(node->dev->flags & IFF_UP))
        ret_dev(NSTATS_I_DOWN);

    if (pid >= PATHS_N)
        ret_node(NSTATS_I_PATH_INVALID);

    path_s* const path = &node->paths[pid];

    if (!(__atomic_load_n(&node->ipaths, __ATOMIC_SEQ_CST) & IPATH(pid)))
        ret_path(PSTATS_I_DISABLED);

    if (i < I_KEYS_DYNAMIC) {
        if (size < XGW_PAYLOAD_MIN)
            // BAD SIZE FOR A NORMAL PACKET
            ret_path(PSTATS_I_SIZE_SMALL);
    } elif (size != PING_SIZE)
            // BAD SIZE FOR A PING PACKET
            ret_path(PSTATS_I_SIZE_NOT_PING);

    if ((PKT_DATA(pkt) + size) > end)
            // WE DON'T HAVE THE ENTIRE PACKET
            ret_path(PSTATS_I_SIZE_TRUNCATED);

    // SITUATION VS PACKET TYPE
    switch (atomic_get(&path->answered)) {

        default: // >= PTIME_MIN
            if (i == I_KEY_SYN)
                // ESTABLISHED RECEBE TUDO MENOS SYN
                ret_path(PSTATS_I_ESTABLISHED_REFUSE_SYN);
            break;

        case ANSWERED_CONNECTING:
            if (i != I_KEY_PONG)
                // CONNECTING SO RECEBE PONGS
                ret_path(PSTATS_I_CONNECTING_REQUIRE_PONG);
            break;

        case ANSWERED_LISTENING:
            if (i == I_KEY_SYN) {
                if (0)
                    // LIMITAR A QUANTIDADE DE SYNS RECEBIVEIS A CADA KEEPER INTERVAL
                    ret_path(PSTATS_I_LISTENING_SYN_TOO_MANY);
                if (ltime != atomic_get(&path->syn))
                    // ELE NAO CONHECE NOSSO CODIGO
                    ret_path(PSTATS_I_LISTENING_SYN_WRONG);
            } elif (i != I_KEY_PING)
                    // LISTENING SO RECEBE SYN E PING
                    ret_path(PSTATS_I_LISTENING_REFUSE_DATA_AND_PONG);
            break;

        case ANSWERED_ACCEPTING:
            // LISTENING, MAS EM ESTADO DE ACCEPTING
            ret_path(PSTATS_I_ACCEPTING);
            break;
    }

    if (i != I_KEY_SYN)
        // NOTE: CONSIDERA QUE O PEER ESTIMOU NOSSO TIME A PARTIR DO RTT CALCULADO POR ELE, QUE PODE SER ATE RTT_MAX (E QUE ESTES SAO DIFERENTES DOS NOSSOS)
        // NOTE: CONSIDERA CLOCK SKELS LOCAL/REMOTE
        // NOTE: CONSIDERA QUE LEVOU UM LATENCY ATÉ CHEGAR AQUI
        // NOTE: CONSIDERA CPU BUSY TIMES
        if (ABS_DIFF(ltime + atomic_get(&path->rtt)/2, path->mask + get_current_ms()) > atomic_get(&path->rtt_var)/2)
            // ELE NAO CONHECE NOSSO TIME (OU TEM UM SKEW GRANDE)
            ret_path(PSTATS_I_LTIME_MISMATCH);

    // DECRYPT
    if (pkt_decrypt(node, i, pkt, size) != hash)
        // CORRUPT
        ret_path(PSTATS_I_HASH_MISMATCH);

    // IS A EXPECTED TYPE FOR OUR STATUS
    // IS AUTHENTIC (hash)
    // IS SYNCED (time)

    if (i >= I_KEY_PING)
        ret_path(in_ping(node, skb, pkt));

    // NORMAL PACKET

    // AVANCA O ALIGNMENT
    void* const orig = PKT_DATA(pkt);

    if (BE8(*(u8*)orig) == 0x45) { // TODO:

        // NOTE: AQUI CONSIDERA O IP4 + PORTAS
        if ((orig + sizeof(ip4_s)) > end)
            ret_path(PSTATS_I_DATA_IP4_TRUNCATED);

#ifdef CONFIG_XGW_GATEWAY_TCP_PROXY
        ip4_s* const ip = orig;

        if (ip->proto == BE8(IPPROTO_TCP)) {
            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            if (BE32(ip->saddr ^ ip->daddr) >> 8) { // TODO:
                // XGW -> INTERNET
                // WILL BE TREATED AS SELF, SO NO NEED FOR TCP CHECKSUM
                skb->mark  = XGW_TCP_PROXY_MARK_4 | BE16(ip->dport);
                ip->dport  = BE16(CONFIG_XGW_GATEWAY_TCP_PROXY_PORT);
            }
        }
#endif

        skb->protocol = BE16(ETH_P_IP);

    } else { ASSERT((BE8(*(u8*)orig) >> 4) == 6);

        if ((orig + sizeof(ip6_s)) > end)
            ret_path(PSTATS_I_DATA_IP6_TRUNCATED);

#ifdef CONFIG_XGW_GATEWAY_TCP_PROXY
        ip6_s* const ip = orig;

        if (ip->proto == BE8(IPPROTO_TCP)) {
            // TODO: SE FOR SYN/SYN-ACK, ADJUST MSS
            if (BE64(ip->saddr[0] ^ ip->daddr[0])) { // TODO:
                // XGW -> INTERNET
                // WILL BE TREATED AS SELF, SO NO NEED FOR TCP CHECKSUM
                skb->mark  = XGW_TCP_PROXY_MARK_6 | BE16(ip->dport);
                ip->dport  = BE16(CONFIG_XGW_GATEWAY_TCP_PROXY_PORT);
            }
        }
#endif

        skb->protocol = BE16(ETH_P_IPV6);
    }

    //
    skb->len            = size;
    skb->data           = orig;
    skb->network_header = orig        - SKB_HEAD(skb); // SKB TRIM QUE NEM É FEITO NO ip_rcv_core()
    skb->tail           = orig + size - SKB_HEAD(skb); // NOTE: NET_SKBUFF_DATA_USES_OFFSET
 // skb->mac_header
 // skb->mac_len
#if 0
    skb->ip_summed      = CHECKSUM_COMPLETE;
    skb->csum_valid     = 1;
    skb->csum_complete_sw = 1;
#else // LIKE WIREGUARD
    skb->ip_summed      = CHECKSUM_UNNECESSARY;
    skb->csum_level     = ~0;
#endif
    skb->dev            = node->dev;
    skb->pkt_type       = PACKET_HOST; // WE MAY BE RECEIVING VIA MULTICAST/BROADCAST
    // TODO: ON OUT: skb->type = PACKET_BROADCAST | PACKET_MULTICAST | PACKET_OTHERHOST | PACKET_OUTGOING

    stat = PSTATS_I_DATA_GOOD;

_ret_path: _stat = path->stats;       goto _ret;
_not_xgw:   stat = DSTATS_I_NOT_XGW; // JUST SOME PACKET, TRAVELING AROUND THE WORLD IN 80 HOPS
_ret_dev:  _stat = dstats;            goto _ret;
_ret_node: _stat = nstats[nid];
_ret:

    stat_inc_count(&_stat[stat].count);
    stat_inc_bytes(&_stat[stat].bytes, skb->len);

    // NOTE QUE TODOS OS STATS PASS SAO 0
    return stat;
}

static void keeper (struct timer_list* const timer) {

    //
    timer->expires = jiffies + KEEPER_INTERVAL_JIFFIES;

#ifdef CONFIG_XGW_BEEP
    uint beep = 0; // O OBJETIVO É BEEPAR CONFORME A SITUAÇÃO DO PIOR node
    // CONFORME OS NODES
#endif

    //
    random64_refresh();

    // LOCK
    unsigned long iflags;

    spin_lock_irqsave(&xlock, iflags);

    const u64 _now = get_current_ms();

    for (node_s* node = knodes; node; node = node->next) {

        ASSERT(!node_is_off(node));
        ASSERT(*node->ptr == node);
        ASSERT(node->info & N_CONNS_N);
        ASSERT(node->info & N_MTU);
        ASSERT(node->info & N_NAME);
     // ASSERT(node->info & N_OADD);
        ASSERT(node->mtu >= MTU_MIN);
        ASSERT(node->mtu <= MTU_MAX);
        ASSERT(node->connsN >= CONNS_MIN);
        ASSERT(node->connsN <= CONNS_MAX);
        ASSERT((node->info   & N_INFO) == node->info);
        ASSERT((node->opaths & OPATHS) == node->opaths);
        ASSERT((node->ipaths & IPATHS) == node->ipaths);
        ASSERT((node->kpaths & KPATHS) == node->kpaths);
        ASSERT((node->opaths & (node->kpaths * OPATH_0)) == node->opaths);
        ASSERT((node->ipaths & (node->kpaths * IPATH_0)) == node->ipaths);
        ASSERT(node->oVersions[O_KEY_PING] == I_KEY_PING);

#ifdef CONFIG_XGW_BEEP // SITUACAO DESTE NODE, CONFORME OS PATHS
        uint stableWeights = 0, stableSum = 0;
#endif

        // BUILD
        u64 opaths = 0;

        // ITERATE
        uint kpaths = node->kpaths;

        while (kpaths) { const uint pid = __ctz(kpaths); kpaths ^= KPATH(pid);

            path_s* const path = &node->paths[pid];

            ASSERT(path->node == node);
            ASSERT(path->rtt <= RTT_MAX);
            ASSERT(path->rtt_max <= RTT_MAX);
            ASSERT(path->rtt <= path->rtt_max);
            ASSERT(path->rtt_var_ >= RTT_VAR_MIN);
            ASSERT(path->rtt_var_ <= RTT_VAR_MAX);
            ASSERT(path->rtt_var >= RTT_VAR_MIN);
            ASSERT(path->rtt_var <= RTT_VAR_MAX_INIT);
            ASSERT(path->rtt_var >= path->rtt_var_);
            ASSERT(path->cdown <= RTT_VAR_STEPS);
            ASSERT(path->tdiff >= TDIFF_MIN);
            ASSERT(path->tdiff <= TDIFF_MAX);
            ASSERT((path->asked    >= PTIME_MIN &&
                    path->asked    <= PTIME_MAX) ||
                    path->asked    == 0);
            ASSERT((path->answered >= PTIME_MIN &&
                    path->answered <= PTIME_MAX) ||
                    path->answered == ANSWERED_LISTENING ||
                    path->answered == ANSWERED_ACCEPTING ||
                    path->answered == ANSWERED_CONNECTING);
            ASSERT(path->mask >= PMASK_MIN);
            ASSERT(path->mask <= PMASK_MAX);
            ASSERT(path->oadd >= PATH_OADD_MIN);
            ASSERT(path->oadd <= PATH_OADD_MAX);

            if (path->info & K_START) { //231956

                if (path->info & P_CLIENT) {

#if 0
                    if (path->info & P_DHCP) {

                        if (1) {
                          // DHCP IS DONE
                          if (path_is_ip4(path)) {
                              ASSERT(dhcp->type == ipv4);
                              // copy ipv4 address to src
                          } elif (path_is_ip6(path)) {
                              ASSERT(dhcp->type == ipv6);
                              // copy ipv6 address to src
                          }
                          // copy phys
                          // copy smac
                          // copy dmac
                          // copy eth protocol
                          // copy vlan id
                        } else
                            // CANNOT START YET
                            goto _skip;
                    }
#endif

                    // THE TTL AND TOS ARE STORED OUTSIDE THE SKEL, OTHERWISE WE LOSE THEM ON EVERY IN-DISCOVER.
                    // SO, THE CMD ALSO STORED THEM DIRECTLY ON PATH.
                    // HERE WE COPY THEM TO THE SKEL
                    if (path_is_ip4(path)) { hdr_ip4_s* const ip4 = PKT_IP4(&path->skel);
                        ip4->tos = BE8(path->tos);
                        ip4->ttl = BE8(path->ttl);
                    } elif (path_is_ip6(path)) { hdr_ip6_s* const ip6 = PKT_IP6(&path->skel);
                        ip6->tos = BE8(path->tos);
                        ip6->ttl = BE8(path->ttl);
                        ip6->flow = BE16(SKEL_IP6_FLOW(node, path));
                    }

                    // TODO: PRECOMPUTE TCP CHECKSUM
                    // TODO: PRECOMPUTE UDP CHECKSUM (FOR IPV6)
                    if (path_is_udp_tcp(path)) {
                        path->sPortIndex = ((uint)path->sPortIndex + 1                      ) % path->sPortsN;
                        path->dPortIndex = ((uint)path->dPortIndex + (path->sPortIndex == 0)) % path->dPortsN;
                        // BOTH UDP AND TCP PORTS START ON TRANSPORT
                        hdr_udp_s* const udp = PKT_UDP(&path->skel);
                        udp->sport = BE16(path->sPorts[path->sPortIndex]);
                        udp->dport = BE16(path->dPorts[path->dPortIndex]);
                    }

                    // TODO: FAZER ISSO A TODOS OS NODES-PATHS AO SETAR O SELF
                    // TODO: TEM QUE REPENSAR O CRYPTO DERIVATE, POIS SENAO SE MUDAR O SELF, TERA DE SETAR NOVAMENTE O SECRET
                    path->skel.x.src   = BE16(nodeSelf);
                    path->acks         = ACKS_CLIENT;
                    path->answered     = ANSWERED_CONNECTING;
                } else {
                    printk("XGW: %s [%s]: LISTENING\n", node->name, path->name);
                    path->skel.type    = 0; //
                    path->acks         = ACKS_SERVER;
                    path->answered     = ANSWERED_LISTENING;
                }   path->asked        = 0; // AINDA NAO ENVIEI PING
                    path->pseen[0]     = 0;
                    path->pseen[1]     = 0;
                    path->rtt          = path->rtt_max / 2;
                    path->rtt_var      = path->rtt_var_ + RTT_VAR_STEPS * RTT_VAR_STEP;
                    path->cdown        = RTT_VAR_STEPS;
                    path->info        ^= K_START | K_LISTEN;
                    path->since        = 0;
                    path->tdiff        = 0;
                    path->mask         = PMASK_MIN + (random64(_now) % (PMASK_MAX - PMASK_MIN));
                 // path->olatency   == ?

                // ENABLE IN
                // NOTE: AQUI ENTAO TEM UM RACE CONDITION, ELE PODE RECEBER UM PING/PONG E COMO SERÁ INTERPRETADO?
                __atomic_store_n(&node->ipaths, node->ipaths | IPATH(pid), __ATOMIC_SEQ_CST);
            }

            if (path->info & K_LISTEN) {

                if (__atomic_load_n(&path->answered, __ATOMIC_SEQ_CST) >= ANSWERED_CONNECTING) {

                    printk("XGW: %s [%s]: %s ON PHYS %s WITH RTT %u +%u\n",
                        node->name, path->name, (path->info & P_SERVER) ? "ACCEPTED" : "CONNECTING", path->skel.phys->name, (uint)path->rtt, (uint)path->rtt_var);

             ASSERT(path->since    == 0);
                    path->info     ^= K_LISTEN | K_ESTABLISHED;
                    path->since     = _now;
                 // AT THIS POINT, THE PATH->SKEL WAS BUILT
                 //      a) FROM USER (CMD)
                 //      b) FROM IN (DISCOVER)
             ASSERT(path->skel.x.src  == BE16(nodeSelf));
             ASSERT(path->skel.x.dst  == BE16(node->nid));
             ASSERT(path->skel.x.path == BE8 (PATH_ID(node, path)));
                 // path->skel.x.version --> ON encrypt()
                 // path->skel.x.dsize   --> ON encrypt()
                 // path->skel.x.time    --> ON encrypt()
                 // path->skel.x.hash    --> ON encrypt()
             ASSERT(path->skel.phys);

                    // PASSA A ENVIAR PINGS
                    const uint q = path->skel.phys->ifindex % PING_QUEUES_N;

                    path->next = pings[q];
                                 pings[q] = path;
                }
            }

            if (path->info & K_ESTABLISHED) {

                u64 acks;

                const u64 answered = atomic_get(&path->answered);

                ASSERT((answered >= PTIME_MIN &&
                        answered <= PTIME_MAX) ||
                        answered == ANSWERED_CONNECTING);

                // SE NAO RECEBEU UM PONG, ESTE RTT SERÁ UM OVERFLOW
                // É POR ISSO QUE ANSWERED_CONNECTING TEM QUE SER MAIOR DO QUE O RTT_MAX,
                // POIS SE O ASKED ESTIVER ZERADO,
                // QUALQUER PATH->ANSWERED QUE NAO SEJA O LAST PING ENVIADO,
                // TEM QUE RESULTAR EM > RTT_MAX
                const uint took = answered - path->asked;

                if (took <= RTT_MAX) {
                    // AVERAGE, CAPPED TO LIMITS
                    uint rtt = ((uint)path->rtt*7 + took*1) / (7 + 1);
                    if (rtt > path->rtt_max)
                        rtt = path->rtt_max;
                    // SAVE THE NEW AVERAGE
                    if (path->cdown) {
                        path->cdown--;
                        __atomic_store_n(&path->rtt_var, path->rtt_var - RTT_VAR_STEP, __ATOMIC_RELAXED);
                    }  // __atomic_store_n(&path->olatency, (rtt + path->rtt_var)/2 + path->oadd, __ATOMIC_RELAXED);
                        __atomic_store_n(&path->rtt, rtt, __ATOMIC_RELAXED);
                    // A SECOND ELAPSED
                    acks = (path->acks >> 1) | ((u64)(took <= (rtt + path->rtt_var)) << (ACKS_N - 1));
                } else
                    acks = (path->acks >> 1);

                if (path->acks != acks) {
                    path->acks = acks;
                    // CHANGED

                    const char* str;

                    switch (acks) {
                        case 0b0000000000000000000000000000000000000000000000000000000000000000ULL: str = "LOST";       break;
                        case 0b1000000000000000000000000000000000000000000000000000000000000000ULL: str = "RECOVERING"; break;
                        case 0b0111111111111111111111111111111111111111111111111111111111111111ULL: str = "UNSTABLE";   break;
                        case 0b1011111111111111111111111111111111111111111111111111111111111111ULL: str = "UNSTABLE (BUT OK)";   break;
                        case 0b1111111111111111111111111111111111111111111111111111111111111111ULL: str = "STABLE";     break;
                        default:                                                                    str = NULL;
                    }

                    if (str) {
                        if (took <= RTT_MAX)
                            printk("XGW: %s [%s]: RTT %u +%u; %s; PONG TOOK %u\n", node->name, path->name, (uint)path->rtt, (uint)path->rtt_var, str, took);
                        else
                            printk("XGW: %s [%s]: RTT %u +%u; %s; PONG LOST\n", node->name, path->name, (uint)path->rtt, (uint)path->rtt_var, str);
                    }

                } elif (!acks) {
                    // TIMED OUT WAITING FOR PONGS
                    printk("XGW: %s [%s]: TIMED OUT\n", node->name, path->name);
                    goto _suspend;
                }

                // DOS PIORES AOS MELHORES
                opaths |= ( // TEM QUE CONSIDERAR QUE ELE VAI ENTRAR NA FRENTE DOS OUTROS ENTAO PERDER 1 PONG E RECEBER UM VAI FORCAR A TROCA E FERRAR A ESTABILIDADE DAS STREAMS
                    ((u64)(acks >= 0b000000000000000000000000000100000000000000000000ULL) << (3*PATHS_N)) | // BASTA QUE ESTEJA FUNCIONANDO ENTAO
                    ((u64)(acks >= 0b010111111110000000000000000000000000000000000000ULL) << (2*PATHS_N)) |
                    ((u64)(acks >= 0b111111111111111111110000000000000000000000000000ULL) << (1*PATHS_N)) | // NOTE: THIS ONE SHOULD BE REPEATED
                    ((u64)(acks >= 0b111111111111111111110000000000000000000000000000ULL) << (0*PATHS_N)) // TODO: REMOVE THIS REPETITION LIMITATION
                ) << pid;
            }

            if (path->info & K_SUSPEND) { // NOTE: WILL EXECUTE TWICE BECAUSE THE ATOMIC EXCHANTE BELOW
_suspend:
                // STOP IN
                // STOP PING (BY REMOVING K_ESTABLISHED)
                // STOP OUT (BY NOT INCLUDING IN OPATHS)
                path->info  = (path->info & P_INFO) | K_SUSPENDING;
                path->acks  = 0; // PARA JA ATUALIZAR O BEEP
                path->since = 0;

                __atomic_store_n(&node->ipaths, node->ipaths & ~IPATH(pid), __ATOMIC_RELAXED);

            } elif (path->info & K_SUSPENDING) { BUILD_ASSERT((uint)N_ON == (uint)P_ON);
                if ((path->info ^= K_SUSPENDING) & node->info & N_ON & P_ON) {
                     path->info |= K_START;
                } else {
                    printk("XGW: %s [%s]: STOPPED\n", node->name, path->name);
                    // NOW THE PATH IS STOPPED
                    // NOTE: THE PATH MAY BE ON, FOR EXAMPLE IF THE PATH STOPPED BECAUSE THE NODE STOPED
                    node->kpaths ^= KPATH(pid);
                }
            }

#ifdef CONFIG_XGW_BEEP
            // NOTE: TEM QUE FAZER ISSO ENQUANTO O NODE E O PATH ESTIVEREM ATIVADOS
            // TODO: MULTIPLICAR POR UM FATOR PARA NAO DEIXAR FICAR UM VALOR PEQUENO, JA QUE NAO PODE USAR FLOAT
            // ASSIM MELHORARA A PRECISAO DO RESULTADO
            if ((uint)(node->info & path->info & N_ON & P_ON) * path->weight * path->weight_acks) {
                stableWeights += (1024 * path->weight);
                stableSum += (popcount(path->acks & ((1ULL << path->weight_acks) - 1)) * (1024 * path->weight)) / path->weight_acks;
            }
#endif
        }

        if (node->info & N_ON) {
            // SALVA

            if (node->opaths != opaths) {
#ifdef CONFIG_XGW_NMAP
                if (!opaths)
                    // O NODE AGORA VAI FICAR SEM PATHS FUNCIONANDO; PASSA A USAR O GW
                    __atomic_store_n(&nmap[node->nid], node->gw, __ATOMIC_SEQ_CST);
                elif (!node->opaths)
                    // O NODE NÃO TINHA PATHS FUNCIONANDO E AGORA TEM; DEIXA DE USAR O GW
                    __atomic_store_n(&nmap[node->nid], node->nid, __ATOMIC_SEQ_CST);
#endif
                __atomic_store_n(&node->opaths, opaths, __ATOMIC_SEQ_CST);
            }

#ifdef CONFIG_XGW_BEEP
            if (node->weights) {
                // (0 ... 1) * BEEP MAX
                const uint q = CONFIG_XGW_BEEP_BASE + (((node->weights - wstable) * (CONFIG_XGW_BEEP_MAX - CONFIG_XGW_BEEP_BASE)) / node->weights);
                if (beep > q)
                    beep = q;
            }
#endif

        } elif (nodes[node->nid] == node) {
            // VAI FORCAR UM INTERVALO SEM O IN/OUT ACESSAR O NODE
            // ALSO NEEDS A BREAK TIME FOR CHANGING COUNTERS

#ifdef CONFIG_XGW_NMAP
            // O NODE AGORA VAI FICAR OFF; PASSA A USAR O GW
            __atomic_store_n(&nmap[node->nid], node->gw, __ATOMIC_SEQ_CST);
#endif
            __atomic_store_n(&node->opaths, 0, __ATOMIC_SEQ_CST);

            ASSERT(!opaths);
            ASSERT(!node->opaths);
            ASSERT(!node->ipaths);

            nodes_set_off(node->nid, node);

        } elif (!node->kpaths) {

            ASSERT(!opaths);
            ASSERT(!node->opaths);
            ASSERT(!node->ipaths);

            __unlink(node);

            printk("XGW: %s: STOPPED\n", node->name);
        }

#ifdef CONFIG_XGW_BEEP // SITUACAO DESTE NODE, CONFORME OS PATHS
        if (node->info & N_ON) {
            stableSum /= stableWeights;
            if (beep < stableSum)
                beep = stableSum;
        }
#endif
    }

    spin_unlock_irqrestore(&xlock, iflags);

    // SEND PINGS
    for_count (q, PING_QUEUES_N) {

        path_s** ptr = &pings[q]; path_s* path;

        while ((path = *ptr)) {
            if (path->info & K_ESTABLISHED) {

                ASSERT((path->asked    >= PTIME_MIN &&
                        path->asked    <= PTIME_MAX) ||
                        path->asked    == 0);
                ASSERT((path->answered >= PTIME_MIN &&
                        path->answered <= PTIME_MAX) ||
                        path->answered == ANSWERED_CONNECTING);
                ASSERT(path->mask     >= PMASK_MIN);
                ASSERT(path->mask     <= PMASK_MAX);
                ASSERT(path->tdiff    >= TDIFF_MIN);
                ASSERT(path->tdiff    <= TDIFF_MAX);

                const u64 now = path->mask + get_current_ms();

                ASSERT(now >= PTIME_MIN);
                ASSERT(now <= PTIME_MAX);

                __atomic_store_n(&path->asked, now, __ATOMIC_RELAXED);

                const uint o =
                    atomic_get(&path->answered) == ANSWERED_CONNECTING ?
                        O_KEY_SYN :
                        O_KEY_PING;

                const u64 rtime = (o == O_KEY_SYN) ?
                    path->syn : RTIME(now, atomic_get(&path->tdiff));

#if 0
                ASSERT((rtime >= PTIME_MIN &&
                        rtime <= PTIME_MAX) ||
                        rtime == path->syn);
#endif
                if (!((rtime >= PTIME_MIN &&
                        rtime <= PTIME_MAX) ||
                        rtime == path->syn)) {
                    printk("XGW: CRAZY: NODE [%s] PATH [%s] now = 0x%016llX rtime = 0x%016llX tdiff %lld \n",
                            path->node->name,
                            path->name,
                            (uintll)now,
                            (uintll)rtime,
                            (long long int)path->tdiff
                        );
                }

                // NOTE: RESERVA HEAD AND TAIL ROOM POIS PODE TER MAIS ENCAPSULAMENTOS NO PHYS
                ping_send(path->node, path, &path->skel, now, rtime, o);

                ptr = &path->next;
            } else // NOTE: NOW PATH->NEXT IS INVALID
               *ptr =  path->next;
        }
    }

    // TODO: IF XGW IS DOWN, STOP BEEP
#ifdef CONFIG_XGW_BEEP
    if (beepStatus != BEEP_STATUS_DISABLED) {
        // BEEP IS NOT DISABLED
        if (beepStatus != BEEP_STATUS_SILENT)
            // ESTAVA TOCANDO AGORA PAUSA
            beep = BEEP_STATUS_SILENT;
        if (beepStatus != beep)
            beep_do((beepStatus = beep));
    }
#endif

    add_timer_on(timer, 0);
}

static DEFINE_TIMER(kTimer, keeper);

// TODO: CONFIRMAR QUE NAO ESTA REPETINDO O LINKING DO PING NO LINKED LIST

static void __optimize_size stats_print (void) {

    for_count (s, DSTATS_N) {

        const uintll c = atomic_get(&(dstats[s].count));
        const uintll b = atomic_get(&(dstats[s].bytes));

        if (c || b)
            printk("XGW: %s %llu %llu\n", statsStrs.d[s], c, b);
    }

    for_count (nid, NODES_N) {

        const node_s* const node = nodes_get_locked_unsuspended(nid);

        if (node) {

            for_count (s, NSTATS_N) {

                const uintll c = atomic_get(&(nstats[nid][s].count));
                const uintll b = atomic_get(&(nstats[nid][s].bytes));

                if (c || b)
                    printk("XGW: %s %s %llu %llu\n", node->name, statsStrs.n[s], c, b);
            }

            for_count (pid, PATHS_N) {

                const path_s* const path = &node->paths[pid];

                if (path->info) { // <----- E SE QUISERMOS VER MESMO ASSIM?

                    for_count (s, PSTATS_N) {

                        const u64 c = atomic_get(&path->stats[s].count);
                        const u64 b = atomic_get(&path->stats[s].bytes);

                        if (c || b)
                            printk("XGW: %s [%s] %s %llu %llu\n", node->name, path->name, statsStrs.p[s], (uintll)c, (uintll)b);
                    }
                }
            }
        }
    }
}

#include "cmd_names.c"
#include "cmd.c"

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

static int __optimize_size dev_up (net_device_s* const dev) {

    // TODO: ATIVA O TIMER
    printk("XGW: UP\n");

    return 0;
}

static int __optimize_size dev_down (net_device_s* const dev) {

    // TODO: DESATIVA O TIMER
    printk("XGW: DOWN\n");

    return 0;
}

static const net_device_ops_s xgwDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  dev_up,
    .ndo_stop             =  dev_down,
    .ndo_start_xmit       =  out,
    .ndo_set_mac_address  =  NULL,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void __cold_as_ice __optimize_size dev_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xgwDevOps;
    dev->header_ops      = NULL;
    dev->type            = ARPHRD_NONE;
    dev->addr_len        = 0; // TODO: 2 nodeSelf ?
    dev->hard_header_len = XGW_HEADROOM + 64; // !!!!!!
    dev->min_header_len  = XGW_HEADROOM + 64; // !!!!!!
    dev->needed_headroom = XGW_HEADROOM + 64; // !!!!!!
    dev->min_mtu         = XGW_PAYLOAD_MIN;
    dev->max_mtu         = XGW_PAYLOAD_MAX;
    dev->mtu             = XGW_PAYLOAD_MAX; // TODO: DETAULT ETH_MTU - (PKT_X_SIZE + PKT_ALIGN_SIZE)
    dev->tx_queue_len    = 0; // DEFAULT_TX_QUEUE_LEN
    dev->flags           = IFF_POINTOPOINT | IFF_NOARP;
    dev->priv_flags     |= IFF_NO_QUEUE | IFF_NO_RX_HANDLER | IFF_LIVE_ADDR_CHANGE;
// !!!!!!!!!!!!!!!!!!!!!!!    dev->lltx = true; // dev->features |= NETIF_F_LLTX
    dev->features |= 0
        | NETIF_F_RXCSUM
//        | NETIF_F_HW_CSUM
#if 1 // !!!!!!!!!!!!!!!!!!!!!!!!
        | NETIF_F_HIGHDMA
#endif
        ;
    dev->hw_features |= 0
        | NETIF_F_RXCSUM
//        | NETIF_F_HW_CSUM
#if 1 // !!!!!!!!!!!!!!!!!!!!!!!!
        | NETIF_F_HIGHDMA
#endif
        ;
    // TODO: hw_enc_features ?
    //
}

// TODO: INTERCEPT MTU CHANGES TO ALLOW ONLY THE NODE/GLOBAL MTU

// CREATE A INTERFACE FOR A NODE
static inline net_device_s* dev_create_node (const char* const name, const uint nid) {

    // CREATE THE VIRTUAL INTERFACE
    net_device_s* const dev = alloc_netdev(sizeof(uint), name, NET_NAME_USER, dev_setup);

    if (dev == NULL) {
        printk("XGW: FAILED TO ALLOCATE\n");
        return NULL;
    }

    *(uint*)netdev_priv(dev) = nid;

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(dev)) {
        // TODO: FREE
        printk("XGW: CREATE FAILED TO REGISTER\n");
        return NULL;
    }

    return dev;
}

static int __init xgw_init (void) {

    //
    BUILD_ASSERT( ( ((uintptr_t)0xffffffffffffffffULL) & (~(uintptr_t)1) ) == (0xffffffffffffffffULL ^ 1) );

    printk("XGW: INIT KEEPER INTERVAL %u MS\n", KEEPER_INTERVAL_MS);
    printk("XGW: V4 PREFIX %08llX WIDTH %u/%u\n", (uintll)V4_PREFIX, V4_WIDTH_PREFIX, V4_WIDTH_NODE);
    printk("XGW: V6 PREFIX %016llX WIDTH %u/%u\n", (uintll)V6_PREFIX, V6_WIDTH_PREFIX, V6_WIDTH_NODE);

    // ESTAMOS PEGANDO TODOS OS ENCAPSULAMENTOS QUE O SISTEMA JA USA, E AUMENTANDO ISSO:
    //  PAD_NO_ENCAP + sizeof(hdr_x_s) + PKT_ALIGN_WORDS*sizeof(u64)
    // PORTANTO:
    //      32 + sizeof(hdr_x_s) + PKT_ALIGN_WORDS*sizeof(u64) = 64
    // DEVERA INFLUENCIAR:
    //  -   LL_MAX_HEADER
    //  -   MAX_HEADER
    // DEFINIDO EM:
    //      include/linux/netdevice.h

    // JA O MTU, INFLUENCIA
    // sizeof(hdr_x_s) + PKT_ALIGN_WORDS*sizeof(u64) = 40

    //BUILD_ASSERT(XGW_HEADROOM_OVERHEAD == (32 + sizeof(hdr_x_s) + sizeof(u64)));
    ASSERT(NET_SKB_PAD >= 128);
    ASSERT(NET_SKB_PAD >= XGW_HEADROOM);
    BUILD_ASSERT(LL_MAX_HEADER == (256 + 64));
    BUILD_ASSERT(MAX_HEADER == (256 + 64 + 64));

    // INITIALIZE EVERYTHING

    // TODO:
    nodeSelf = 0;

    gwsN = 0;

    //
    random64_init();

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
    kTimer.expires = jiffies + KEEPER_LAUNCH_DELAY_SECS * HZ;
    add_timer(&kTimer);

    // EXPOSE CMD
    proc_create("xgw", 0600, NULL, &xgwProcOps);

    return 0;
}

late_initcall(xgw_init);

BUILD_ASSERT(XGW_MTU_OVERHEAD == (PKT_X_SIZE + PKT_ALIGN_SIZE));

BUILD_ASSERT((PKT_DATA((pkt_s*)NULL) - NULL) == (ENCAP_SIZE + XGW_MTU_OVERHEAD));

//
BUILD_ASSERT(CMD_SIZE(NODE_NAME) == sizeof(((node_s*)NULL)->name));
BUILD_ASSERT(CMD_SIZE(PATH_NAME) == sizeof(((path_s*)NULL)->name));
BUILD_ASSERT(CMD_SIZE(ADDR4)     == sizeof(((path_s*)NULL)->skel.encap_ip4.ip4.saddr));
BUILD_ASSERT(CMD_SIZE(ADDR4)     == sizeof(((path_s*)NULL)->skel.encap_ip4.ip4.daddr));
BUILD_ASSERT(CMD_SIZE(ADDR6)     == sizeof(((path_s*)NULL)->skel.encap_ip6.ip6.saddr));
BUILD_ASSERT(CMD_SIZE(ADDR6)     == sizeof(((path_s*)NULL)->skel.encap_ip6.ip6.daddr));
BUILD_ASSERT(CMD_SIZE(MAC)       == sizeof(((path_s*)NULL)->skel.encap_eth.eth.dmac));
BUILD_ASSERT(CMD_SIZE(MAC)       == sizeof(((path_s*)NULL)->skel.encap_eth.eth.smac));

//
BUILD_ASSERT((CMD_TYPE(NODE_ID)) NID_MAX == NID_MAX);
BUILD_ASSERT((CMD_TYPE(PATH_ID)) PID_MAX == PID_MAX);
BUILD_ASSERT((CMD_TYPE(CODE))    CMDS_N  == CMDS_N);

//
BUILD_ASSERT(sizeof(hdr_eth_s)  == 14);
BUILD_ASSERT(sizeof(hdr_vlan_s) ==  4);
BUILD_ASSERT(sizeof(hdr_ppp_s)  ==  8);
BUILD_ASSERT(sizeof(hdr_ip4_s)  == 20);
BUILD_ASSERT(sizeof(hdr_ip6_s)  == 40);
BUILD_ASSERT(sizeof(hdr_udp_s)  ==  8);
BUILD_ASSERT(sizeof(hdr_tcp_s)  == 20);
BUILD_ASSERT(sizeof(hdr_x_s)    == 24);

//
BUILD_ASSERT(sizeof(encap_eth_s)              == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip4_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip6_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip4_udp_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ip6_udp_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_s)         == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip4_s)     == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip6_s)     == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip4_udp_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ip6_udp_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ppp_s)     == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ppp_ip4_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_vlan_ppp_ip6_s) == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ppp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ppp_ip4_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_eth_ppp_ip6_s)      == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip4_s)              == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip4_udp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip4_tcp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip6_s)              == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip6_udp_s)          == ENCAP_SIZE);
BUILD_ASSERT(sizeof(encap_ip6_tcp_s)          == ENCAP_SIZE);

//
BUILD_ASSERT(offsetof(pkt_s, x) == ENCAP_SIZE);

//
BUILD_ASSERT(offsetof(pkt_s, encap_raw) == 0);

//
BUILD_ASSERT(sizeof(pkt_s) == (ENCAP_SIZE + sizeof(hdr_x_s)));

BUILD_ASSERT(sizeof(hdr_x_s) == PKT_X_SIZE);
BUILD_ASSERT(sizeof(pkt_s)   == PKT_SIZE);
BUILD_ASSERT(sizeof(ping_s)  == PING_SIZE);

//
BUILD_ASSERT(sizeof(ip4_s) == (sizeof(hdr_ip4_s) + 2 * sizeof(u16)));
BUILD_ASSERT(sizeof(ip6_s) == (sizeof(hdr_ip6_s) + 2 * sizeof(u16)));

// MIN < MAX
BUILD_ASSERT(RTT_VAR_MIN < RTT_VAR_MAX);
BUILD_ASSERT(PATH_OADD_MIN < PATH_OADD_MAX);

// TEM QUE TER UMA FOLGUINHA...
BUILD_ASSERT((RTT_MAX + 100) < KEEPER_INTERVAL_MS);

//
BUILD_ASSERT(offsetof(path_s, info)        % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(path_s, stats)       % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, opaths)      % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, nid)         % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, syns)        % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, paths)       % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, oKeys)       % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, iKeys)       % CACHE_LINE_SIZE == 0);
BUILD_ASSERT(offsetof(node_s, secret)      % CACHE_LINE_SIZE == 0);

BUILD_ASSERT(sizeof(path_s) == PATH_SIZE);

//
BUILD_ASSERT((sizeof(((path_s*)NULL)->acks)*8) == ACKS_N);

BUILD_ASSERT(sizeof(((path_s*)NULL)->stats)
         >= (sizeof(((path_s*)NULL)->stats[0]) * PSTATS_N));

//
BUILD_ASSERT(sizeof(((node_s*)NULL)->oKeys)  == (O_KEYS_ALL * K_SIZE));
BUILD_ASSERT(sizeof(((node_s*)NULL)->iKeys)  == (I_KEYS_ALL * K_SIZE));
BUILD_ASSERT(sizeof(((node_s*)NULL)->secret) == (SECRET_KEYS_N * K_SIZE));
BUILD_ASSERT(sizeof(((node_s*)NULL)->syns)   == 128);
BUILD_ASSERT(sizeof(((node_s*)NULL)->paths)  == 12288);

// -- NAO PRECISAREMOS CHECAR LIMITES, POIS NAO CABEM MESMO
// -- E TEM QUE CABER TODOS
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->src))     ~(typeof(((hdr_x_s*)NULL)->src))     0 == NID_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->dst))     ~(typeof(((hdr_x_s*)NULL)->dst))     0 == NID_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->version)) ~(typeof(((hdr_x_s*)NULL)->version)) 0 == I_KEY_MAX);
BUILD_ASSERT((typeof(((ping_s*)NULL)->ver))      ~(typeof(((ping_s*)NULL)->ver))      0 == I_KEY_MAX);

// THE TYPES MUST BE ABLE TO HOLD THEIR VALUES
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt))         RTT_MAX          == RTT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt_max))     RTT_MAX          == RTT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt_var_))    RTT_VAR_MAX      == RTT_VAR_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->rtt_var))     RTT_VAR_MAX_INIT == RTT_VAR_MAX_INIT);
BUILD_ASSERT((typeof(((path_s*)NULL)->cdown))       RTT_VAR_STEPS    == RTT_VAR_STEPS);
BUILD_ASSERT((typeof(((path_s*)NULL)->oadd))        PATH_OADD_MAX    == PATH_OADD_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->acks))        ACKS_SERVER      == ACKS_SERVER);
BUILD_ASSERT((typeof(((path_s*)NULL)->acks))        ACKS_CLIENT      == ACKS_CLIENT);
BUILD_ASSERT((typeof(((path_s*)NULL)->since))       RTIME_MAX        == RTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->asked))       PTIME_MAX        == PTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->answered))    PTIME_MAX        == PTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pseen[0]))    PTIME_MAX        == PTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->pseen[1]))    PTIME_MAX        == PTIME_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->tdiff))       TDIFF_MIN        == TDIFF_MIN);
BUILD_ASSERT((typeof(((path_s*)NULL)->tdiff))       TDIFF_MAX        == TDIFF_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->info))        P_INFO           == P_INFO);
BUILD_ASSERT((typeof(((path_s*)NULL)->info))        P_ALL            == P_ALL);
BUILD_ASSERT((typeof(((path_s*)NULL)->weight))      PATH_WEIGHT_MAX  == PATH_WEIGHT_MAX);
BUILD_ASSERT((typeof(((path_s*)NULL)->weight_acks)) ACKS_N           == ACKS_N);
//BUILD_ASSERT((typeof(((path_s*)NULL)->sPortsN))     PATH_PORTS_N     == PATH_PORTS_N);
//BUILD_ASSERT((typeof(((path_s*)NULL)->dPortsN))     PATH_PORTS_N     == PATH_PORTS_N);
//BUILD_ASSERT((typeof(((path_s*)NULL)->sPortIndex))  (PATH_PORTS_N-1) == (PATH_PORTS_N-1));
//BUILD_ASSERT((typeof(((path_s*)NULL)->dPortIndex))  (PATH_PORTS_N-1) == (PATH_PORTS_N-1));
BUILD_ASSERT((typeof(((node_s*)NULL)->nid))         NID_MAX          == NID_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->mtu))         MTU_MAX          == MTU_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->weights))     NODE_WEIGHTS_MAX == NODE_WEIGHTS_MAX);
BUILD_ASSERT((typeof(((node_s*)NULL)->kpaths))      KPATH(PID_MAX)   == KPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->opaths))      OPATH(PID_MAX)   == OPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->ipaths))      IPATH(PID_MAX)   == IPATH(PID_MAX));
BUILD_ASSERT((typeof(((node_s*)NULL)->kpaths))      KPATHS           == KPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->opaths))      OPATHS           == OPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->ipaths))      IPATHS           == IPATHS);
BUILD_ASSERT((typeof(((node_s*)NULL)->info))        N_INFO           == N_INFO);
BUILD_ASSERT((typeof(((ping_s*)NULL)->ver))         I_KEY_MAX        == I_KEY_MAX);
BUILD_ASSERT((typeof(((ping_s*)NULL)->time))        PTIME_MAX        == PTIME_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->src))        NID_MAX          == NID_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->dst))        NID_MAX          == NID_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->path))       PID_MAX          == PID_MAX);
BUILD_ASSERT((typeof(((hdr_x_s*)NULL)->time))       PTIME_MAX        == PTIME_MAX);

BUILD_ASSERT(sizeof(((ping_s*)NULL)->rnd)       == K_SIZE);
BUILD_ASSERT(sizeof(((node_s*)NULL)->secret[0]) == K_SIZE);
BUILD_ASSERT(sizeof(((node_s*)NULL)->secret) == SECRET_SIZE);

//BUILD_ASSERT((typeof(((node_s*)NULL)->info))N_INFO == N_INFO);
//BUILD_ASSERT((typeof(((node_s*)NULL)->connsN))CONNS_N_MAX == CONNS_N_MAX);

//
BUILD_ASSERT(P_INFO == (
    P_ON                  +
    P_CLIENT              +
    P_SERVER              +
    P_PHYS                +
    P_MAC_SRC             +
    P_MAC_DST             +
    P_ADDR_SRC            +
    P_ADDR_DST            +
    P_PORT_SRC            +
    P_PORT_DST            +
    P_TOS                 +
    P_TTL                 +
    P_VPROTO              +
    P_VID                 +
    P_RTT_VAR             +
    P_NAME                +
    P_DHCP                +
    P_DHCP_MAC_DST_SERVER +
    P_DHCP_MAC_DST_GW     +
    P_EXIST
));

BUILD_ASSERT(P_ALL == (
    P_INFO                +
    K_START               +
    K_SUSPEND             +
    K_SUSPENDING          +
    K_LISTEN              +
    K_ESTABLISHED
));

// MATCH THE TOOL
BUILD_ASSERT(CMDS_N == 87);
BUILD_ASSERT(CMD_ERRS_N == 76);

BUILD_ASSERT(TDIFF_MIN < 0);
BUILD_ASSERT(TDIFF_MAX > 0);

BUILD_ASSERT(RTIME_MIN < RTIME_MAX);
BUILD_ASSERT(PTIME_MIN < PTIME_MAX);
BUILD_ASSERT(TDIFF_MIN < TDIFF_MAX);

//
BUILD_ASSERT((PMASK_MAX + RTIME_MAX + TDIFF_MAX) < 0xFFFFFFFFFFFFFFFFULL);

BUILD_ASSERT((s64)PTIME_MIN == PTIME_MIN);
BUILD_ASSERT((s64)PTIME_MAX == PTIME_MAX);

BUILD_ASSERT(-((s64)PTIME_MIN - (s64)PTIME_MAX)
           == (     PTIME_MAX -      PTIME_MIN));

BUILD_ASSERT(CONNS_MIN > 1);
BUILD_ASSERT(CONNS_MAX < (1*1024*1024));

BUILD_ASSERT(CONNS_MIN < CONNS_MAX);

// TODO: REVIEW ALL RESTRICT
