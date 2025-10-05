
// É ISSO QUE TEM QUE SER RETIRADO DO MTU DA INTERFACE XGW
// (E TAMBEM OS DEMAIS ENCAPSULAMENTOS DO PHYS)
#define XGW_MTU_OVERHEAD 40

#define PKT_X_SIZE 24

#define PKT_ALIGN_SIZE  16
#define PKT_ALIGN_WORDS 2

#define XGW_PAYLOAD_MIN     28 // AN EMPTY IPV4/UDP
#define XGW_PAYLOAD_MAX 0xFFFF // MUST FIT ON PKT->SIZE
// TODO: XGW_PAYLOAD_MAX TEM QUE SER 65536, E PKT->DSIZE ENCODED COM -1 E DECODED COM +1

#define PKT_DATA(pkt) PTR((pkt)->p + PKT_ALIGN_WORDS)

//
#define TOS_MAX 0xFF

//
#define TTL_MIN 0x01
#define TTL_MAX 0xFF

// TODO:
#define IPPROTO_XGW 0x99

// TODO:
#define ETH_P_XGW 0x2562

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
} ;

struct hdr_udp_s {
    u16 sport;
    u16 dport;
    u16 size;
    u16 cksum;
};

struct hdr_x_s { // WIRE
    union {
        struct {
            u16 src;
            u16 dst;
            u8  path; // BEM NO MEIO PARA PROTEGE-LO NO HASHING
            u8  version;
            u16 dsize; // SIZE OF THE PAYLOAD (WIRE) OR HEADER (RUNTIME)
        };  u64 info;
    };
    u64 time; // DESTINATION'S TIME (NO CASO DO PONG, O PKT->TIME É O RAW PING->RTIME SENDO RESPONDIDO)
    u64 hash;
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

// MAXIMUM SIZE
// (? + ETH + VLAN + PPPOE + IP6 + TCP)
// (2 + 14  + 4    + 8     + 40  + 20 )
#define ENCAP_SIZE 88

// ENCAP_SIZE + sizeof(hdr_x_s)
#define PKT_SIZE 112

#define __ETH  (1 << 0)
#define __VLAN (1 << 1)
#define __IP4  (1 << 2)
#define __IP6  (1 << 3)
#define __TCP  (1 << 4)
#define __UDP  (1 << 5)

#define __PPP  (1 << 6)

#define H_TYPES_N (1 << 7)

enum H_TYPE {
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

// THE SIZE OF THE HEADERS
enum H_SIZE {
    H_SIZE_RAW              = sizeof(hdr_x_s),
    H_SIZE_IP4              = sizeof(hdr_x_s)  + sizeof(hdr_ip4_s),
    H_SIZE_IP4_UDP          = sizeof(hdr_x_s)  + sizeof(hdr_ip4_s)  + sizeof(hdr_udp_s),
    H_SIZE_IP4_TCP          = sizeof(hdr_x_s)  + sizeof(hdr_ip4_s)  + sizeof(hdr_tcp_s),
    H_SIZE_IP6              = sizeof(hdr_x_s)  + sizeof(hdr_ip6_s),
    H_SIZE_IP6_UDP          = sizeof(hdr_x_s)  + sizeof(hdr_ip6_s)  + sizeof(hdr_udp_s),
    H_SIZE_IP6_TCP          = sizeof(hdr_x_s)  + sizeof(hdr_ip6_s)  + sizeof(hdr_tcp_s),
    H_SIZE_ETH              = sizeof(hdr_x_s)  + sizeof(hdr_eth_s),
    H_SIZE_ETH_IP4          = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ip4_s),
    H_SIZE_ETH_IP4_UDP      = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ip4_s)   + sizeof(hdr_udp_s),
    H_SIZE_ETH_IP4_TCP      = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ip4_s)   + sizeof(hdr_tcp_s),
    H_SIZE_ETH_IP6          = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ip6_s),
    H_SIZE_ETH_IP6_UDP      = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ip6_s)   + sizeof(hdr_udp_s),
    H_SIZE_ETH_IP6_TCP      = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ip6_s)   + sizeof(hdr_tcp_s),
    H_SIZE_ETH_VLAN         = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_vlan_s),
    H_SIZE_ETH_VLAN_IP4     = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_vlan_s)  + sizeof(hdr_ip4_s),
    H_SIZE_ETH_VLAN_IP4_UDP = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_vlan_s)  + sizeof(hdr_ip4_s)   + sizeof(hdr_udp_s),
    H_SIZE_ETH_VLAN_IP4_TCP = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_vlan_s)  + sizeof(hdr_ip4_s)   + sizeof(hdr_tcp_s),
    H_SIZE_ETH_VLAN_IP6     = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_vlan_s)  + sizeof(hdr_ip6_s),
    H_SIZE_ETH_VLAN_IP6_UDP = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_vlan_s)  + sizeof(hdr_ip6_s)   + sizeof(hdr_udp_s),
    H_SIZE_ETH_VLAN_IP6_TCP = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_vlan_s)  + sizeof(hdr_ip6_s)   + sizeof(hdr_tcp_s),
    H_SIZE_ETH_VLAN_PPP     = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ppp_s)   + sizeof(hdr_vlan_s),
    H_SIZE_ETH_VLAN_PPP_IP4 = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ppp_s)   + sizeof(hdr_vlan_s)  + sizeof(hdr_ip4_s),
    H_SIZE_ETH_VLAN_PPP_IP6 = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ppp_s)   + sizeof(hdr_vlan_s)  + sizeof(hdr_ip6_s),
    H_SIZE_ETH_PPP          = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ppp_s),
    H_SIZE_ETH_PPP_IP4      = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ppp_s)   + sizeof(hdr_ip4_s),
    H_SIZE_ETH_PPP_IP6      = sizeof(hdr_x_s)  + sizeof(hdr_eth_s)  + sizeof(hdr_ppp_s)   + sizeof(hdr_ip6_s),
};

// THE OFFSET FROM THE PKT TO THE HEADERS
enum H_OFFSET {
    H_OFFSET_RAW              = PKT_SIZE - H_SIZE_RAW,
    H_OFFSET_ETH              = PKT_SIZE - H_SIZE_ETH,
    H_OFFSET_ETH_IP4          = PKT_SIZE - H_SIZE_ETH_IP4,
    H_OFFSET_ETH_IP6          = PKT_SIZE - H_SIZE_ETH_IP6,
    H_OFFSET_ETH_IP4_UDP      = PKT_SIZE - H_SIZE_ETH_IP4_UDP,
    H_OFFSET_ETH_IP6_UDP      = PKT_SIZE - H_SIZE_ETH_IP6_UDP,
    H_OFFSET_ETH_VLAN         = PKT_SIZE - H_SIZE_ETH_VLAN,
    H_OFFSET_ETH_VLAN_IP4     = PKT_SIZE - H_SIZE_ETH_VLAN_IP4,
    H_OFFSET_ETH_VLAN_IP6     = PKT_SIZE - H_SIZE_ETH_VLAN_IP6,
    H_OFFSET_ETH_VLAN_IP4_UDP = PKT_SIZE - H_SIZE_ETH_VLAN_IP4_UDP,
    H_OFFSET_ETH_VLAN_IP6_UDP = PKT_SIZE - H_SIZE_ETH_VLAN_IP6_UDP,
    H_OFFSET_ETH_VLAN_PPP     = PKT_SIZE - H_SIZE_ETH_VLAN_PPP,
    H_OFFSET_ETH_VLAN_PPP_IP4 = PKT_SIZE - H_SIZE_ETH_VLAN_PPP_IP4,
    H_OFFSET_ETH_VLAN_PPP_IP6 = PKT_SIZE - H_SIZE_ETH_VLAN_PPP_IP6,
    H_OFFSET_ETH_PPP          = PKT_SIZE - H_SIZE_ETH_PPP,
    H_OFFSET_ETH_PPP_IP4      = PKT_SIZE - H_SIZE_ETH_PPP_IP4,
    H_OFFSET_ETH_PPP_IP6      = PKT_SIZE - H_SIZE_ETH_PPP_IP6,
    H_OFFSET_IP4              = PKT_SIZE - H_SIZE_IP4,
    H_OFFSET_IP6              = PKT_SIZE - H_SIZE_IP6,
    H_OFFSET_IP4_UDP          = PKT_SIZE - H_SIZE_IP4_UDP,
    H_OFFSET_IP4_TCP          = PKT_SIZE - H_SIZE_IP4_TCP,
    H_OFFSET_IP6_UDP          = PKT_SIZE - H_SIZE_IP6_UDP,
    H_OFFSET_IP6_TCP          = PKT_SIZE - H_SIZE_IP6_TCP,
};

// NOTE: ESSA PORRA DESSE ALINHAMENTO NAO ESTA DEIXANDO OS 64-BIT WORDS ALINHADOS PARA PROCESSARMOS
#define XGW_HEADROOM (sizeof(pkt_s) + (PKT_ALIGN_WORDS * sizeof(u64)))

// ESTAMOS PEGANDO TODOS OS ENCAPSULAMENTOS QUE O SISTEMA JA USA, E AUMENTANDO ISSO:
//  PAD_NO_ENCAP + sizeof(hdr_x_s) + PKT_ALIGN_WORDS*sizeof(u64)
// PORTANTO:
//      32 + sizeof(hdr_x_s) + PKT_ALIGN_WORDS*sizeof(u64) = 64
// DEVERA INFLUENCIAR:
//  -   LL_MAX_HEADER
//  -   MAX_HEADER
// DEFINIDO EM:
//      include/linux/netdevice.h
//BUILD_ASSERT(XGW_HEADROOM_OVERHEAD == (32 + sizeof(hdr_x_s) + sizeof(u64)));

BUILD_ASSERT(LL_MAX_HEADER == 196 );
BUILD_ASSERT(MAX_HEADER == (196 + 48));

// JA O MTU, INFLUENCIA
// sizeof(hdr_x_s) + PKT_ALIGN_WORDS*sizeof(u64) = 40

#define __

// TODO: __packed? ARM?
struct pkt_s {
    union { // ENCAP
                                  char encap_raw [H_OFFSET_RAW              ];
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
            u16 hsize;
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

// TODO: TODOS OS ENCAP_S TEM QUE SER < ENCAP_MAX

#define PKT_ETH(pkt)   ((hdr_eth_s*)(PTR(pkt) + (pkt)->moffset))
#define PKT_VLAN(pkt) ((hdr_vlan_s*)(PTR(pkt) + (pkt)->noffset))
#define PKT_PPP(pkt)   ((hdr_ppp_s*)(PTR(pkt) + (pkt)->_reserved))
#define PKT_IP4(pkt)   ((hdr_ip4_s*)(PTR(pkt) + (pkt)->Noffset))
#define PKT_IP6(pkt)   ((hdr_ip6_s*)(PTR(pkt) + (pkt)->Noffset))
#define PKT_UDP(pkt)   ((hdr_udp_s*)(PTR(pkt) + (pkt)->toffset))
#define PKT_TCP(pkt)   ((hdr_tcp_s*)(PTR(pkt) + (pkt)->toffset))
