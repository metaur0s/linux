
#include <linux/time.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/eventpoll.h>
#include <net/sock.h>
#include <net/tcp.h>

// linux/poll.h -> uapi/linux/eventpoll.h

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

typedef __s32 i32;

typedef unsigned int uint;

#define EPOLL_DATA(idx, fd) ((((u64)(idx)) << 32) | ((u64)(fd)))
#define EPOLL_DATA_IDX(epoll_data) ((epoll_data) >> 32)
#define EPOLL_DATA_FD(epoll_data)  ((epoll_data) & 0xFFFFFFFFU)

typedef struct superpoll_result_s {
    u32 time; // EM MS
    u32 idx;
    u32 fd;
    i32 receive_ret; // RETURN OF THE RECVFROM()
    char received[];
} superpoll_result_s;

enum : uint {
    EPOLL_SUPER_SIZE = 256*1024,
    EPOLL_WAIT_SUPER_EVENTS_N = (sizeof(superpoll_result_s) + EPOLL_SUPER_SIZE + sizeof(struct epoll_event)) / sizeof(struct epoll_event),

    SOCKADDRLEN_IPV4 = sizeof(struct sockaddr_in),
    SOCKADDRLEN_IPV6 = sizeof(struct sockaddr_in6),
};

enum : uint {
    MYSOCKET_OPTS__ITFC                = 1U <<  0,
    MYSOCKET_OPTS__MARK                = 1U <<  1,
    MYSOCKET_OPTS__KEEPALIVE           = 1U <<  2,
    MYSOCKET_OPTS__BIND                = 1U <<  3,
    MYSOCKET_OPTS__TCP_NODELAY         = 1U <<  4,
    MYSOCKET_OPTS__TCP_QUICKACK        = 1U <<  5,
    MYSOCKET_OPTS__TCP_SYNCNT          = 1U <<  6,
    MYSOCKET_OPTS__TCP_KEEPALIVE_COUNT = 1U <<  7,
    MYSOCKET_OPTS__TCP_KEEPALIVE_INTVL = 1U <<  8,
    MYSOCKET_OPTS__TCP_KEEPALIVE_IDLE  = 1U <<  9,
    MYSOCKET_OPTS__TCP_USER_TIMEOUT    = 1U << 10,
};

typedef struct mysocket_opts_s {
    u16 flags;
    u8  addrlen;
    u8  reserved8;
    u32 type;
    u32 protocol;
    u32 mark;
    u32 rcv_size;
    u32 snd_size;
    u32 keepalive;
    u32 tcp_nodelay;
    u32 tcp_quickack;
    u32 tcp_syncnt;
    u32 tcp_keepalive_count;
    u32 tcp_keepalive_idle;
    u32 tcp_keepalive_intvl;
    u32 tcp_user_timeout;
    char itfc [16]; // IFNAMSIZ
    union {
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } addr_bind;
    union {
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } addr_connect;
} mysocket_opts_s;
