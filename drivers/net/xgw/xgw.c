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
#elif 1
#define ASSERT(c) __attribute__((assume(c)))
#else
#define ASSERT(c) ({})
#endif

#define CACHE_LINE_SIZE 64

//
#define KEEPER_INTERVAL_MS 900
#define KEEPER_INTERVAL_JIFFIES ((9 * HZ) / 10)

#define KEEPER_LAUNCH_DELAY_SECS 4

// HASHEIA E AGRUPA POR INTERFACE INDEX
// NOTE: SE MUDAR DE INTERFACE VAI TER QUE REMOVER DA LISTA PRIMEIRO, E SÓ DEPOIS JOGAR PARA OUTRO
#define PING_QUEUES_N 8

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

#define ANSWERED_LISTENING  ((u64)0)
#define ANSWERED_ACCEPTING  ((u64)1)
#define ANSWERED_CONNECTING ((u64)2048) // TEM QUE SER GRANDE SUFICIENTE PARA QUE ((path->answered - path->asked) > RTT_MAX)

// REAL TIME (KTIME) (~2 YEARS IN MS)
#define RTIME_MIN ((u64)8192)
#define RTIME_MAX ((u64)0x1800000000ULL)

//
#define PTIME_MIN (PMASK_MIN + RTIME_MIN)
#define PTIME_MAX (PMASK_MAX + RTIME_MAX)

// MAX DIFFERENCE FROM LOCAL PTIME TO PEER PTIME
#define TDIFF_MIN ((s64)PTIME_MIN - (s64)PTIME_MAX)
#define TDIFF_MAX ((s64)PTIME_MAX - (s64)PTIME_MIN)

#include "base.h"
#include "types.h"
#include "ports.h"
#include "random.h"
#include "crypto.h"
#include "ping.h"
#include "pkt.h"
#include "stats.h"
#include "nodes.h"
#include "cmd_codes.h"
#include "cmd_errs.h"
#include "cmd_args_types.h"

DEFINE_SPINLOCK(xlock);

static volatile u64 _xrnd [RANDOM_LEN];
static net_device_s* xgw;
static node_s* knodes;
static u16 nodeSelf;
static u8 gwsN;
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

// EXPOSED TO KERNEL
// net/core/dev.c WILL USE US
#define in xgw_dev_in

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

#include "alloc.c"
#ifdef CONFIG_XGW_BEEP
#include "beep.c"
#endif
#include "random.c"
#include "ports.c"
#include "crypto.c"
#include "pkt_skels.c"
#include "pkt_encap.c"
#include "out.c"
#include "ping.c"
#include "in_discover.c"
#include "in.c"
#include "keeper.c"
#include "stats.c"
#include "dev.c"
#include "cmd_names.c"
#include "cmd.c"
#include "asserts.c"

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

    //
    BUILD_ASSERT( ( ((uintptr_t)0xffffffffffffffffULL) & (~(uintptr_t)1) ) == (0xffffffffffffffffULL ^ 1) );

    printk("XGW: INIT KEEPER INTERVAL %u MS\n", KEEPER_INTERVAL_MS);
    printk("XGW: V4 PREFIX %08llX WIDTH %u/%u\n", (uintll)V4_PREFIX, V4_WIDTH_PREFIX, V4_WIDTH_NODE);
    printk("XGW: V6 PREFIX %016llX WIDTH %u/%u\n", (uintll)V6_PREFIX, V6_WIDTH_PREFIX, V6_WIDTH_NODE);

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

// TODO: REVIEW ALL RESTRICT
