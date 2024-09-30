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

#include "base.h"
#include "types.h"

#define CACHE_LINE_SIZE 64

#ifdef CONFIG_XGW_GATEWAY
#define XGW_TCP_PROXY_MARK_4 0x25440000U
#define XGW_TCP_PROXY_MARK_6 0x25660000U
#endif

// ALL UDP PORTS
#define UDP_PORTS_N 65536

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

#define SECRET_PAIRS_N 1024

#define SECRET_SIZE 65536

// DO QUAL DERIVAREMOS O SECRET
#define PASSWORD_SIZE_MIN    16
#define PASSWORD_SIZE_MAX 65536

//
#define PASSWORD_ROUNDS 16

//
#define KEEPER_INTERVAL ((9 * HZ) / 10)

// HASHEIA E AGRUPA POR INTERFACE INDEX
// NOTE: SE MUDAR DE INTERFACE VAI TER QUE REMOVER DA LISTA PRIMEIRO, E SÓ DEPOIS JOGAR PARA OUTRO
#define PING_QUEUES_N 8

//
#define PORTS_N (UDP_PORTS_N / PORTS_WIDTH)

#define PORTS_WIDTH 32
#define PORTS_SHIFT 5
#define PORTS_MASK 0b11111
#define PORTS_W (ports[port >> PORTS_SHIFT])
#define PORTS_B (1 << (port & PORTS_MASK))

typedef int ports_t;

#include "pkt.h"
#include "stats.h"
#include "nodes.h"
#include "dhcp.h"
#include "cmd.h"

DEFINE_SPINLOCK(xlock);

static volatile u64 _xrnd;
static net_device_s* xgw;
static node_s* knodes;
static u16 nodeSelf;
static u8 gwsN;
static u16 gws [GWS_N]; // TODO: PODE DEIXAR DUAS ARRAYS E MODIFICAR A QUE NAO ESTA SENDO USADA
static node_s* volatile nodes [NODES_N];
static volatile ports_t ports [PORTS_N];
static volatile stat_s dstats           [DSTATS_N];
static volatile stat_s nstats [NODES_N] [NSTATS_N];
#ifdef CONFIG_XGW_NMAP
static volatile u16 nmap [NODES_N];
#endif

// NEED TO BE SEPARATE
//    - SO IT CAN BE USET WITHOUT THE LOCK
//    - SO IT CAN BE USET WITH INTERRUPTS ENABLED
//    - SO IT CAN BE DONE ONCE
//    - SO IT CAN BE DONE PER INTERFACE HASH
static path_s* pings [PING_QUEUES_N];

static void paged_free (void* const a, const size_t size);
static void* paged_alloc (const size_t size);

static u64 random64 (const u64 seed);

static inline void ports_enable (const uint port);
static inline void ports_disable (const uint port);
static inline ports_t ports_is_enabled (const uint port);

static void __cold_as_ice __optimize_size stats_print (void);

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
#include "alloc.c"

// TODO: SO APRENDER UM PATH SE TAL PORTA ESTIVER CONFIGURADA NELE
static inline void ports_enable (const uint port)
    { PORTS_W |= PORTS_B; }

static inline void ports_disable (const uint port)
    { PORTS_W &= ~PORTS_B; }

static inline ports_t ports_is_enabled (const uint port)
    { return PORTS_W & PORTS_B; }

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

// NAO É RANDOM NO SENTIDO DE NAO ADIVINHAVEL, MAS FICA NAO TAO SEQUENCIAL E ALTERANDO DIFERENTES BITS
static u64 random64 (const u64 seed) {

#ifdef CONFIG_XGW_RDRAND
    u64 R; __builtin_ia32_rdrand64_step(&R);
#else // TODO:
    u64 R = 0;
#endif

    return atomic_add(&_xrnd, _swap64(_swap64(_xrnd + seed) + __builtin_ia32_rdtsc()) + R);
}

// vai ter que retirar o erro node_is_self :S ?
//  ou nao vai poder setar o self comoum que ja existe
// e nem crar um que seja o self

struct proc_ops xgwProcOps = {
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
