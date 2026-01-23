
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/eventpoll.h> // speedyb0y
#include <net/sock.h>


static inline int __sys_setsockopt_my (int fd, int level, int optname, char __user *user_optval, int optlen) {

    return 0;
}



