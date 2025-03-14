
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
#define P_LATENCY_MIN         (1U << 14)
#define P_LATENCY_MAX         (1U << 15)
#define P_LATENCY_VAR         (1U << 16)
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

#define LATENCY_MIN 10
#define LATENCY_MAX 625

#define LATENCY_VAR_MIN 10
#define LATENCY_VAR_MAX 120

// ITS THE LATENCY + LATENCY_VAR
#define LATENCY_EFFECTIVE_MIN 20
#define LATENCY_EFFECTIVE_MAX 650

// NOTE: NAO ADIANTA SER MUITO LONGO POIS OS KEYS PODEM ACABAR SENDO INUTILIZADOS
// NOTE: NAO ADIANTA SER LONGO POIS FICARA UM TEMPAO TRAVADO (SERVER)
// NOTE: NAO ADIANTA SER LONGO POIS FICARA UM TEMPAO TRAVADO (CLIENT)
// EM SEGUNDOS
#define PATH_TIMEOUT_MIN   1
#define PATH_TIMEOUT_MAX 255

//
#define PATH_SIZE 256

struct path_s {
// 64 -- KEEPER / IN
    // RO
    u32 info; // KEEPER
    u8  pid;
    u8  timeout; // KEEPER | EM SEGUNDOS
    u8  weight;
    u8  weight_acks;
    u16 latency_min; // KEEPER / IN
    u16 latency_max; // KEEPER / IN
    u16 latency_var; // KEEPER / IN / OUT
    u16 latency;     // KEEPER WRITE / OUT READ  <<---- VAI TER QUE ENFIAR ESSA PORRA ENTÃO DENTRO DO CACHE LINE DO SKEL, OU NO NODE
    // --
    u64 acks; // KEEPER - HISTORY
    u64 syn; // O PKT->TIME QUE O CLIENTE VAI USAR, ENQUANTO NAO DESCOBRE ELE
    u64 pingSent;     // LTIME | WHEN I ASKED - PARA SABER SE ACEITA O PONG
    u64 pongReceived; // LTIME | WHEN I WAS ANSWERED - PARA SABER QUE A CONEXÃO ESTÁ VIVA
    u64 pingSeen;     // RTIME | LAST PING->TIME RECEIVED (HIS RAW TIME) - SO WE DON'T ACCEPT REPEATED/GOINGBACKS
    u64 pongSeen;     // RTIME | LAST PONG->TIME RECEIVED (HIS RAW TIME) - SO WE DON'T ACCEPT REPEATED/GOINGBACKS
// 32 -- KEEPER / PING
    node_s* node; // KEEPER_SEND_PINGS
    path_s* next; // KEEPER_SEND_PINGS -- NA LISTA DE PINGS - ONLY VALID WHEN PATH STATUS >= K_UNSTABLE
    u64 reserved64;
    u16 reserved16;
    u8  tos; // KEEPER / IN_DISCOVER
    u8  ttl; // KEEPER / IN_DISCOVER
    u8  sPortIndex;
    u8  sPortsN;
    u8  dPortIndex;
    u8  dPortsN;
// 48 -- RO (ALMOST) - KEEPER ON START
    u64 since;
    u32 starts;
    char name [PATH_NAME_SIZE];
    u16 sPorts [PATH_PORTS_N]; // EM BIG ENDIAN
    u16 dPorts [PATH_PORTS_N];
// 112 -- IN READ, OUT READ, IN WRITE (ON RECEIVE PING, WHILE OUT IS DISABLED)
    pkt_s skel;
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
    u16 reserved16;
    s64 tdiff;
    u64 tlast; //
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
// 4096 -- PATHS
    path_s paths [PATHS_N];
// 8192 --
    volatile stat_s pstats [PATHS_N] [32];
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
