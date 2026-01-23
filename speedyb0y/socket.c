
#include "asm-generic/errno.h"
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

typedef unsigned int uint;

// É AO CONTRARIO DA IMPLEMENTAÇÃO FEITA NO USER MODE
#define EPOLL_DATA(id, fd) ((((u64)(fd)) << 32) | ((u64)(id)))

enum {
    EPOLL_SUPER_SIZE = (256 + 1) * 1024,
    EPOLL_WAIT_SUPER_EVENTS_N = EPOLL_SUPER_SIZE / sizeof(struct epoll_event),

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

#define set_opt(member, s, n) \
    if (do_sock_setsockopt(sock, compat, s, n, optval, sizeof(params.member))) \
        goto _err_close;

#define set_opt_if_flag(FLAG, member, s, n) \
    if (flags & MYSOCKET_OPTS__##FLAG) { \
        optval.user = (void*)user_optval + offsetof(mysocket_opts_s, member); \
        if (do_sock_setsockopt(sock, compat, s, n, optval, sizeof(params.member))) \
            goto _err_close; \
    }

static inline int __sys_setsockopt_my (const int epoll_fd, const int idx, char __user* const user_optval, const int optlen) {

	int ret;

    if (optlen <= sizeof(mysocket_opts_s)) {
        ret = -EINVAL;
        goto _err;
    }

    mysocket_opts_s params;

    //
    if (copy_from_user(&params, user_optval, sizeof(mysocket_opts_s))) {
        ret = -EFAULT;
        goto _err;
    }

    // CRIA O SOCKET
    const int sock_fd = __sys_socket(params.addr_connect.v4.sin_family, params.type, params.protocol);

    if (sock_fd < 0) {
        ret = sock_fd;
    	goto _err;
    }

    // __sys_connect_file
    CLASS(fd, f)(sock_fd);

    struct socket* const sock = sock_from_file(fd_file(f));

    const bool compat = in_compat_syscall();

    sockptr_t optval = USER_SOCKPTR(user_optval);

    set_opt(rcv_size, SOL_SOCKET, SO_RCVBUF);
    set_opt(snd_size, SOL_SOCKET, SO_SNDBUF);

    const uint flags = params.flags;

    // SET SOCKET OPTIONS
    set_opt_if_flag(MARK,                mark,                SOL_SOCKET, SO_MARK);
    set_opt_if_flag(ITFC,                itfc,                SOL_SOCKET, SO_BINDTODEVICE);
    set_opt_if_flag(TCP_NODELAY,         tcp_nodelay,         SOL_TCP,    TCP_NODELAY);
    set_opt_if_flag(TCP_QUICKACK,        tcp_quickack,        SOL_TCP,    TCP_QUICKACK);
    set_opt_if_flag(TCP_SYNCNT,          tcp_syncnt,          SOL_TCP,    TCP_KEEPCNT);
    set_opt_if_flag(TCP_KEEPALIVE_COUNT, tcp_keepalive_count, SOL_TCP,    TCP_SYNCNT);
    set_opt_if_flag(TCP_KEEPALIVE_IDLE,  tcp_keepalive_idle,  SOL_TCP,    TCP_KEEPIDLE);
    set_opt_if_flag(TCP_KEEPALIVE_INTVL, tcp_keepalive_intvl, SOL_TCP,    TCP_KEEPINTVL);
    set_opt_if_flag(TCP_USER_TIMEOUT,    tcp_user_timeout,    SOL_TCP,    TCP_USER_TIMEOUT);
    set_opt_if_flag(KEEPALIVE,           keepalive,           SOL_SOCKET, SO_KEEPALIVE);

    // BIND
    if (flags & MYSOCKET_OPTS__BIND)
        // __sys_bind_socket
        if ((ret = sock->ops->bind(sock, (void*)&params.addr_bind, params.addrlen)))
            goto _err_close;

    // ADD IT TO THE EPOLL
    struct epoll_event event = {
        .events = EPOLLHUP | EPOLLRDHUP | EPOLLERR | EPOLLPRI | EPOLLOUT,
        .data = EPOLL_DATA(idx, sock_fd)
    };

    if ((ret = do_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &event, false)))
        goto _err_close;

    // CONNECT
    // __sys_connect_file
    if ((ret = sock->ops->connect(sock, (struct sockaddr_unsized *)&params.addr_connect, params.addrlen, sock->file->f_flags | 0)) == 0 || ret == -EINPROGRESS)
        return sock_fd;

_err_close: // TODO: ENTAO FECHAR O FD

    printk("LEAKING FILE DESCRIPTOR!!!\n");

_err:
    return ret;
}
