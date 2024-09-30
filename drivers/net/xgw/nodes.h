
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
    u64 reserved64;
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
