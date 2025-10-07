
//
#define CONNS_MIN CONFIG_XGW_CONNS_MIN
#define CONNS_MAX CONFIG_XGW_CONNS_MAX

//
#define CONNS_SIZE(connsN) ((connsN) * sizeof(u64))

//
#define NODE_NAME_SIZE 32
#define PATH_NAME_SIZE 16 // "broad-bandz-p4u\0"

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

// TODO: ASSERT( (typeof(node->weights))(PATH_WEIGHT_MAX * PATHS_N) == (PATH_WEIGHT_MAX * PATHS_N) )
#define PATH_WEIGHT_MAX 255

// TODO: AUMENTAR ESTE PMASK_MIN, E AI O RTIME_MIN SERA 0
#define PMASK_MIN ((u64)0x0000000000010000ULL)
#define PMASK_MAX ((u64)0x2000000000000000ULL)

// HOW MANY ACKS IN HISTORY (WORD WIDTH IN BITS)
#define ACKS_N 64

// NOTE: NAO ADIANTA SER MUITO LONGO POIS OS KEYS FICAM SENDO INUTILIZADOS
// NOTE: NAO ADIANTA SER MUITO LONGO POIS FICA SEM SINCRONIA
#define ACKS_SERVER (((u64)1) << 32)
#define ACKS_CLIENT (((u64)1) << 63)

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
#define P_RTT_VAR             (1U << 14)
#define P_NAME                (1U << 15)
#define P_DHCP                (1U << 16)
#define P_DHCP_MAC_DST_SERVER (1U << 17)
#define P_DHCP_MAC_DST_GW     (1U << 18)
#define P_EXIST               (1U << 19)
// TODO: P_INFO_WEIGHT_NODE
// TODO: P_INFO_WEIGHT_ACKS
#define P_INFO               ((1U << 20) - 1)
#define K_START               (1U << 20)
#define K_SUSPEND             (1U << 21)
#define K_SUSPENDING          (1U << 22)
#define K_LISTEN              (1U << 23) // TODO: RENAME TO K_DISCOVERING
#define K_ESTABLISHED         (1U << 24) // TODO: RENAME TO K_PINGING
#define P_ALL                ((1U << 25) - 1)

// P_VPROTO -> NOTE: IT IS THE ETH->PROTO, NOT THE VLAN->PROTO

// INFORMACOES QUE SAO PERDIDAS AO MUDAR O TIPO DE ENCAPSULAMENTO
// TODO: P_DHCP ?
#define __P_TYPE_CLR (P_MAC_SRC | P_MAC_DST | P_ADDR_SRC | P_ADDR_DST | P_VPROTO | P_VID | P_DHCP)

#define RTT_MAX 768

//
#define RTT_VAR_MIN    0
#define RTT_VAR_MAX 2048

// TEM QUE CONSIDERAR A DEMORA PARA IR ATUALIZANDO O RTT
// 20 * 300 = 6000 (MAX SKEW FOR RTT)
// 6000 / 2 = 3000 (MAX SKEW FOR RTT/2)
#define RTT_VAR_STEPS 20
#define RTT_VAR_STEP 300

//
#define RTT_VAR_MAX_INIT (RTT_VAR_MAX + RTT_VAR_STEPS * RTT_VAR_STEP)

//
#define PATH_OADD_MIN   1
#define PATH_OADD_MAX 255

// TODO: REMOVER ISSO
// TODO: N_OADD
// TODO: CMD_NODE_OADD_SET
#define PATH_OADD_DEFAULT 64

//
#define PATH_SIZE 768

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

// A ARRAY DE INPUT É PARA AGUENTAR DEMORA/PERDA DE PACOTES
// A CADA INTERVALO SAO ENVIADOS UM PING POR PATH *ATIVO*
#define I_KEYS_ALL     256
#define I_KEYS_DYNAMIC 253 // NAO TEM QUE CONSIDERAR O OVERFLOW POIS NO KEEPER NAO PRECISA SER ATOMIC
#define I_KEY_PING     253
#define I_KEY_PONG     254 // TEM QUE CABER E PREENCHER O PKT->VERSION
#define I_KEY_SYN      255
#define I_KEY_MAX      255

// A ARRAY DE OUTPUT É PARA NAO PRECISAR DE LOCK
#define O_KEYS_ALL     11
#define O_KEYS_DYNAMIC  8 // TEM QUE SER DAR OVERFLOW CONFORME NODE->OCYCLE
#define O_KEY_PING      8
#define O_KEY_PONG      9
#define O_KEY_SYN      10
#define O_KEY_MAX      10

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

// FOR THE NODE
#define NODE_WEIGHTS_MAX (PATHS_N * PATH_WEIGHT_MAX)

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
