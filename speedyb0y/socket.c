
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/eventpoll.h>
#include <net/sock.h>

// linux/poll.h -> uapi/linux/eventpoll.h

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

typedef unsigned int uint;

#define EPOLL_DATA(id, fd) ((((u64)(id)) << 32) | ((u64)(fd)))

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
    struct epoll_event event;
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

static inline int __sys_setsockopt_my (int fd, int level, int optname, char __user* user_optval, int optlen) {

	int ret;

    if (optlen <= sizeof(mysocket_opts_s))
        return -EINVAL;

    sockptr_t optval = USER_SOCKPTR(user_optval);

    bool compat = in_compat_syscall();

    CLASS(fd, f)(fd);

    sock = sock_from_file(fd_file(f));

    if (unlikely(!sock))
	return -ENOTSOCK;

    mysocket_opts_s params;

    //
    if (copy_from_user(&params, user_optval, sizeof(mysocket_opts_s)))
        return -EFAULT;

    // CRIA O SOCKET
    const int sock_fd = __sys_socket(params.addr_connect.v4.sin_family, params.type, params.protocol);

    if (sock_fd < 0)
    	goto _err;

      // ADD IT TO THE EPOLL
      params.event.data = (((u64)sock_fd) << 32) | (u64)level;

      // __sys_connect_file
      CLASS(fd, f)(sock_fd);

      struct socket* const sock = sock_from_file(fd_file(f));

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

      // TODO: BIND

      if (do_epoll_ctl(fd, EPOLL_CTL_ADD, sock_fd, &params.event, false))
        // TODO: ENTAO FECHAR O FD
        return -EINVAL;

      // CONNECT
      // __sys_connect_file
      READ_ONCE(sock->ops)->connect(sock, (struct sockaddr_unsized *)&params.addr_connect, params.addrlen, sock->file->f_flags | 0);

      return sock_fd;

_err:
      return ret;
}
