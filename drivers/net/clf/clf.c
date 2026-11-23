
#include "pkt.h"
#include "paths.h"
#include "cmd.h"

DEFINE_SPINLOCK(xlock);

static uint opaths;
static path_s paths[PATHS_N];

#include "io.c"
#include "cmd.c"

static struct proc_ops procOps = {
    .proc_write = cmd,
};

static int __init clf_init (void) {

    //
    BUILD_ASSERT( ( ((uintptr_t)0xffffffffffffffffULL) & (~(uintptr_t)1) ) == (0xffffffffffffffffULL ^ 1) );

    printk("CLF: INIT\n");

    // INITIALIZE EVERYTHING
    opaths = 0;

    memset((void*)paths,  0, sizeof(ports));
//    memset((void*)nodes,  0, sizeof(nodes));

    // CREATE THE VIRTUAL INTERFACE
    clf = alloc_netdev(0, "clf", NET_NAME_USER, dev_setup);

    if (clf == NULL) {
        printk("CLF: FAILED TO ALLOCATE\n");
        return -1;
    }

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(clf)) {
        printk("CLF: CREATE FAILED TO REGISTER\n");
        return -1;
    }

    // EXPOSE CMD
    proc_create("clf", 0600, NULL, &procOps);

    return 0;
}

late_initcall(clf_init);
