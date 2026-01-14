// SPDX-License-Identifier: GPL-2.0
/*
 * sysctl_net_ipv4.c: sysctl interface to net IPV4 subsystem.
 *
 * Begun April 1, 1996, Mike Shaver.
 * Added /proc/sys/net/ipv4 directory entry (empty =) ). [MS]
 */

#include <linux/sysctl.h>
#include <linux/seqlock.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/cipso_ipv4.h>
#include <net/ping.h>
#include <net/protocol.h>
#include <net/netevent.h>

static int tcp_app_win_max = 31;
static int tcp_min_snd_mss_min = TCP_MIN_SND_MSS;
static int tcp_min_snd_mss_max = 65535;
static int tcp_rto_max_max = TCP_RTO_MAX_SEC * MSEC_PER_SEC;
static unsigned long ip_ping_group_range_min[] = { 0, 0 };
static unsigned long ip_ping_group_range_max[] = { GID_T_MAX, GID_T_MAX };
static u32 u32_max_div_HZ = UINT_MAX / HZ;
static int one_day_secs = 24 * 3600;
static u32 fib_multipath_hash_fields_all_mask __maybe_unused =
	FIB_MULTIPATH_HASH_FIELD_ALL_MASK;
static unsigned int tcp_child_ehash_entries_max = 16 * 1024 * 1024;
static unsigned int udp_child_hash_entries_max = UDP_HTABLE_SIZE_MAX;
static int tcp_plb_max_rounds = 31;
static int tcp_plb_max_cong_thresh = 256;
static unsigned int tcp_tw_reuse_delay_max = TCP_PAWS_MSL * MSEC_PER_SEC;
static int tcp_ecn_mode_max = 2;
static u32 icmp_errors_extension_mask_all =
	GENMASK_U8(ICMP_ERR_EXT_COUNT - 1, 0);

/* obsolete */
static int sysctl_tcp_low_latency __read_mostly;


static void inet_get_ping_group_range_table(const struct ctl_table *table,
					    kgid_t *low, kgid_t *high)
{
	kgid_t *data = table->data;
	struct net *net =
		container_of(table->data, struct net, ipv4.ping_group_range.range);
	unsigned int seq;
	do {
		seq = read_seqbegin(&net->ipv4.ping_group_range.lock);

		*low = data[0];
		*high = data[1];
	} while (read_seqretry(&net->ipv4.ping_group_range.lock, seq));
}

/* Update system visible IP port range */
static void set_ping_group_range(const struct ctl_table *table,
				 kgid_t low, kgid_t high)
{
	kgid_t *data = table->data;
	struct net *net =
		container_of(table->data, struct net, ipv4.ping_group_range.range);
	write_seqlock(&net->ipv4.ping_group_range.lock);
	data[0] = low;
	data[1] = high;
	write_sequnlock(&net->ipv4.ping_group_range.lock);
}

/* Validate changes from /proc interface. */
static int ipv4_ping_group_range(const struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct user_namespace *user_ns = current_user_ns();
	int ret;
	unsigned long urange[2];
	kgid_t low, high;
	struct ctl_table tmp = {
		.data = &urange,
		.maxlen = sizeof(urange),
		.mode = table->mode,
		.extra1 = &ip_ping_group_range_min,
		.extra2 = &ip_ping_group_range_max,
	};

	inet_get_ping_group_range_table(table, &low, &high);
	urange[0] = from_kgid_munged(user_ns, low);
	urange[1] = from_kgid_munged(user_ns, high);
	ret = proc_doulongvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		low = make_kgid(user_ns, urange[0]);
		high = make_kgid(user_ns, urange[1]);
		if (!gid_valid(low) || !gid_valid(high))
			return -EINVAL;
		if (urange[1] < urange[0] || gid_lt(high, low)) {
			low = make_kgid(&init_user_ns, 1);
			high = make_kgid(&init_user_ns, 0);
		}
		set_ping_group_range(table, low, high);
	}

	return ret;
}

static int ipv4_fwd_update_priority(const struct ctl_table *table, int write,
				    void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net;
	int ret;

	net = container_of(table->data, struct net,
			   ipv4.sysctl_ip_fwd_update_priority);
	ret = proc_dou8vec_minmax(table, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV4_FWD_UPDATE_PRIORITY_UPDATE,
					net);

	return ret;
}

static int proc_tcp_congestion_control(const struct ctl_table *ctl, int write,
				       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(ctl->data, struct net,
				       ipv4.tcp_congestion_control);
	char val[TCP_CA_NAME_MAX];
	struct ctl_table tbl = {
		.data = val,
		.maxlen = TCP_CA_NAME_MAX,
	};
	int ret;

	tcp_get_default_congestion_control(net, val);

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = tcp_set_default_congestion_control(net, val);
	return ret;
}

static int proc_tcp_available_congestion_control(const struct ctl_table *ctl,
						 int write, void *buffer,
						 size_t *lenp, loff_t *ppos)
{
	struct ctl_table tbl = { .maxlen = TCP_CA_BUF_MAX, };
	int ret;

	tbl.data = kmalloc(tbl.maxlen, GFP_USER);
	if (!tbl.data)
		return -ENOMEM;
	tcp_get_available_congestion_control(tbl.data, TCP_CA_BUF_MAX);
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	kfree(tbl.data);
	return ret;
}

static int proc_allowed_congestion_control(const struct ctl_table *ctl,
					   int write, void *buffer,
					   size_t *lenp, loff_t *ppos)
{
	struct ctl_table tbl = { .maxlen = TCP_CA_BUF_MAX };
	int ret;

	tbl.data = kmalloc(tbl.maxlen, GFP_USER);
	if (!tbl.data)
		return -ENOMEM;

	tcp_get_allowed_congestion_control(tbl.data, tbl.maxlen);
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = tcp_set_allowed_congestion_control(tbl.data);
	kfree(tbl.data);
	return ret;
}

static int proc_tcp_available_ulp(const struct ctl_table *ctl,
				  int write, void *buffer, size_t *lenp,
				  loff_t *ppos)
{
	struct ctl_table tbl = { .maxlen = TCP_ULP_BUF_MAX, };
	int ret;

	tbl.data = kmalloc(tbl.maxlen, GFP_USER);
	if (!tbl.data)
		return -ENOMEM;
	tcp_get_available_ulp(tbl.data, TCP_ULP_BUF_MAX);
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	kfree(tbl.data);

	return ret;
}

static int proc_tcp_ehash_entries(const struct ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
				       ipv4.sysctl_tcp_child_ehash_entries);
	struct inet_hashinfo *hinfo = net->ipv4.tcp_death_row.hashinfo;
	int tcp_ehash_entries;
	struct ctl_table tbl;

	tcp_ehash_entries = hinfo->ehash_mask + 1;

	/* A negative number indicates that the child netns
	 * shares the global ehash.
	 */
	if (!net_eq(net, &init_net) && !hinfo->pernet)
		tcp_ehash_entries *= -1;

	memset(&tbl, 0, sizeof(tbl));
	tbl.data = &tcp_ehash_entries;
	tbl.maxlen = sizeof(int);

	return proc_dointvec(&tbl, write, buffer, lenp, ppos);
}


#ifdef CONFIG_IP_ROUTE_MULTIPATH
static int proc_fib_multipath_hash_policy(const struct ctl_table *table, int write,
					  void *buffer, size_t *lenp,
					  loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
	    ipv4.sysctl_fib_multipath_hash_policy);
	int ret;

	ret = proc_dou8vec_minmax(table, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV4_MPATH_HASH_UPDATE, net);

	return ret;
}

static int proc_fib_multipath_hash_fields(const struct ctl_table *table, int write,
					  void *buffer, size_t *lenp,
					  loff_t *ppos)
{
	struct net *net;
	int ret;

	net = container_of(table->data, struct net,
			   ipv4.sysctl_fib_multipath_hash_fields);
	ret = proc_douintvec_minmax(table, write, buffer, lenp, ppos);
	if (write && ret == 0)
		call_netevent_notifiers(NETEVENT_IPV4_MPATH_HASH_UPDATE, net);

	return ret;
}

static u32 proc_fib_multipath_hash_rand_seed __ro_after_init;

static void proc_fib_multipath_hash_init_rand_seed(void)
{
	get_random_bytes(&proc_fib_multipath_hash_rand_seed,
			 sizeof(proc_fib_multipath_hash_rand_seed));
}

static void proc_fib_multipath_hash_set_seed(struct net *net, u32 user_seed)
{
	struct sysctl_fib_multipath_hash_seed new = {
		.user_seed = user_seed,
		.mp_seed = (user_seed ? user_seed :
			    proc_fib_multipath_hash_rand_seed),
	};

	WRITE_ONCE(net->ipv4.sysctl_fib_multipath_hash_seed, new);
}

static int proc_fib_multipath_hash_seed(const struct ctl_table *table, int write,
					void *buffer, size_t *lenp,
					loff_t *ppos)
{
	struct sysctl_fib_multipath_hash_seed *mphs;
	struct net *net = table->data;
	struct ctl_table tmp;
	u32 user_seed;
	int ret;

	mphs = &net->ipv4.sysctl_fib_multipath_hash_seed;
	user_seed = mphs->user_seed;

	tmp = *table;
	tmp.data = &user_seed;

	ret = proc_douintvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		proc_fib_multipath_hash_set_seed(net, user_seed);
		call_netevent_notifiers(NETEVENT_IPV4_MPATH_HASH_UPDATE, net);
	}

	return ret;
}
#else

static void proc_fib_multipath_hash_init_rand_seed(void)
{
}

static void proc_fib_multipath_hash_set_seed(struct net *net, u32 user_seed)
{
}

#endif

static struct ctl_table ipv4_table[] = {
	{
		.procname	= "tcp_max_orphans",
		.data		= &sysctl_tcp_max_orphans,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "inet_peer_threshold",
		.data		= &inet_peer_threshold,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "inet_peer_minttl",
		.data		= &inet_peer_minttl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "inet_peer_maxttl",
		.data		= &inet_peer_maxttl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "tcp_mem",
		.maxlen		= sizeof(sysctl_tcp_mem),
		.data		= &sysctl_tcp_mem,
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
#ifdef CONFIG_NETLABEL
	{
		.procname	= "cipso_cache_enable",
		.data		= &cipso_v4_cache_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cipso_cache_bucket_size",
		.data		= &cipso_v4_cache_bucketsize,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cipso_rbm_optfmt",
		.data		= &cipso_v4_rbm_optfmt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cipso_rbm_strictvalid",
		.data		= &cipso_v4_rbm_strictvalid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif /* CONFIG_NETLABEL */
	{
		.procname	= "tcp_available_ulp",
		.maxlen		= TCP_ULP_BUF_MAX,
		.mode		= 0444,
		.proc_handler   = proc_tcp_available_ulp,
	},
	{
		.procname	= "udp_mem",
		.data		= &sysctl_udp_mem,
		.maxlen		= sizeof(sysctl_udp_mem),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "fib_sync_mem",
		.data		= &sysctl_fib_sync_mem,
		.maxlen		= sizeof(sysctl_fib_sync_mem),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= &sysctl_fib_sync_mem_min,
		.extra2		= &sysctl_fib_sync_mem_max,
	},
};

static struct ctl_table ipv4_net_table[] = {
	{
		.procname	= "tcp_max_tw_buckets",
		.data		= &init_net.ipv4.tcp_death_row.sysctl_max_tw_buckets,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "icmp_ignore_bogus_error_responses",
		.data		= &init_net.ipv4.sysctl_icmp_ignore_bogus_error_responses,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE
	},
	{
		.procname	= "icmp_errors_use_inbound_ifaddr",
		.data		= &init_net.ipv4.sysctl_icmp_errors_use_inbound_ifaddr,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE
	},
	{
		.procname	= "icmp_errors_extension_mask",
		.data		= &init_net.ipv4.sysctl_icmp_errors_extension_mask,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &icmp_errors_extension_mask_all,
	},
	{
		.procname	= "icmp_ratelimit",
		.data		= &init_net.ipv4.sysctl_icmp_ratelimit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_ms_jiffies,
	},
	{
		.procname	= "icmp_ratemask",
		.data		= &init_net.ipv4.sysctl_icmp_ratemask,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "icmp_msgs_per_sec",
		.data		= &init_net.ipv4.sysctl_icmp_msgs_per_sec,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "icmp_msgs_burst",
		.data		= &init_net.ipv4.sysctl_icmp_msgs_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "ping_group_range",
		.data		= &init_net.ipv4.ping_group_range.range,
		.maxlen		= sizeof(gid_t)*2,
		.mode		= 0644,
		.proc_handler	= ipv4_ping_group_range,
	},
#ifdef CONFIG_NET_L3_MASTER_DEV
	{
		.procname	= "raw_l3mdev_accept",
		.data		= &init_net.ipv4.sysctl_raw_l3mdev_accept,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "tcp_ecn",
		.data		= &init_net.ipv4.sysctl_tcp_ecn,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &tcp_ecn_mode_max,
	},
	{
		.procname	= "tcp_ecn_option",
		.data		= &init_net.ipv4.sysctl_tcp_ecn_option,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	{
		.procname	= "tcp_ecn_option_beacon",
		.data		= &init_net.ipv4.sysctl_tcp_ecn_option_beacon,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_THREE,
	},
	{
		.procname	= "tcp_ecn_fallback",
		.data		= &init_net.ipv4.sysctl_tcp_ecn_fallback,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "ip_dynaddr",
		.data		= &init_net.ipv4.sysctl_ip_dynaddr,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "ip_no_pmtu_disc",
		.data		= &init_net.ipv4.sysctl_ip_no_pmtu_disc,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "ip_forward_use_pmtu",
		.data		= &init_net.ipv4.sysctl_ip_fwd_use_pmtu,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "ip_forward_update_priority",
		.data		= &init_net.ipv4.sysctl_ip_fwd_update_priority,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler   = ipv4_fwd_update_priority,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "ip_nonlocal_bind",
		.data		= &init_net.ipv4.sysctl_ip_nonlocal_bind,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "ip_autobind_reuse",
		.data		= &init_net.ipv4.sysctl_ip_autobind_reuse,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname	= "fwmark_reflect",
		.data		= &init_net.ipv4.sysctl_fwmark_reflect,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "tcp_fwmark_accept",
		.data		= &init_net.ipv4.sysctl_tcp_fwmark_accept,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
#ifdef CONFIG_NET_L3_MASTER_DEV
	{
		.procname	= "tcp_l3mdev_accept",
		.data		= &init_net.ipv4.sysctl_tcp_l3mdev_accept,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "tcp_mtu_probing",
		.data		= &init_net.ipv4.sysctl_tcp_mtu_probing,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "tcp_base_mss",
		.data		= &init_net.ipv4.sysctl_tcp_base_mss,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tcp_min_snd_mss",
		.data		= &init_net.ipv4.sysctl_tcp_min_snd_mss,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &tcp_min_snd_mss_min,
		.extra2		= &tcp_min_snd_mss_max,
	},
	{
		.procname	= "tcp_mtu_probe_floor",
		.data		= &init_net.ipv4.sysctl_tcp_mtu_probe_floor,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &tcp_min_snd_mss_min,
		.extra2		= &tcp_min_snd_mss_max,
	},
	{
		.procname	= "igmp_link_local_mcast_reports",
		.data		= &init_net.ipv4.sysctl_igmp_llm_reports,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "igmp_max_memberships",
		.data		= &init_net.ipv4.sysctl_igmp_max_memberships,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "igmp_max_msf",
		.data		= &init_net.ipv4.sysctl_igmp_max_msf,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
#ifdef CONFIG_IP_MULTICAST
	{
		.procname	= "igmp_qrv",
		.data		= &init_net.ipv4.sysctl_igmp_qrv,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE
	},
#endif
	{
		.procname	= "tcp_congestion_control",
		.data		= &init_net.ipv4.tcp_congestion_control,
		.mode		= 0644,
		.maxlen		= TCP_CA_NAME_MAX,
		.proc_handler	= proc_tcp_congestion_control,
	},
	{
		.procname	= "tcp_available_congestion_control",
		.maxlen		= TCP_CA_BUF_MAX,
		.mode		= 0444,
		.proc_handler   = proc_tcp_available_congestion_control,
	},
	{
		.procname	= "tcp_allowed_congestion_control",
		.maxlen		= TCP_CA_BUF_MAX,
		.mode		= 0644,
		.proc_handler   = proc_allowed_congestion_control,
	},
	{
		.procname	= "tcp_notsent_lowat",
		.data		= &init_net.ipv4.sysctl_tcp_notsent_lowat,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname	= "tcp_tw_reuse",
		.data		= &init_net.ipv4.sysctl_tcp_tw_reuse,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	{
		.procname	= "tcp_tw_reuse_delay",
		.data		= &init_net.ipv4.sysctl_tcp_tw_reuse_delay,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= &tcp_tw_reuse_delay_max,
	},
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	{
		.procname	= "fib_multipath_use_neigh",
		.data		= &init_net.ipv4.sysctl_fib_multipath_use_neigh,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "fib_multipath_hash_policy",
		.data		= &init_net.ipv4.sysctl_fib_multipath_hash_policy,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_fib_multipath_hash_policy,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_THREE,
	},
	{
		.procname	= "fib_multipath_hash_fields",
		.data		= &init_net.ipv4.sysctl_fib_multipath_hash_fields,
		.maxlen		= sizeof(u32),
		.mode		= 0644,
		.proc_handler	= proc_fib_multipath_hash_fields,
		.extra1		= SYSCTL_ONE,
		.extra2		= &fib_multipath_hash_fields_all_mask,
	},
	{
		.procname	= "fib_multipath_hash_seed",
		.data		= &init_net,
		.maxlen		= sizeof(u32),
		.mode		= 0644,
		.proc_handler	= proc_fib_multipath_hash_seed,
	},
#endif
#ifdef CONFIG_NET_L3_MASTER_DEV
	{
		.procname	= "udp_l3mdev_accept",
		.data		= &init_net.ipv4.sysctl_udp_l3mdev_accept,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "tcp_sack",
		.data		= &init_net.ipv4.sysctl_tcp_sack,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "tcp_window_scaling",
		.data		= &init_net.ipv4.sysctl_tcp_window_scaling,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "tcp_early_retrans",
		.data		= &init_net.ipv4.sysctl_tcp_early_retrans,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_FOUR,
	},
	{
		.procname	= "tcp_dsack",
		.data		= &init_net.ipv4.sysctl_tcp_dsack,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "tcp_app_win",
		.data		= &init_net.ipv4.sysctl_tcp_app_win,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &tcp_app_win_max,
	},
	{
		.procname	= "tcp_rcvbuf_low_rtt",
		.data		= &init_net.ipv4.sysctl_tcp_rcvbuf_low_rtt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname	= "tcp_tso_win_divisor",
		.data		= &init_net.ipv4.sysctl_tcp_tso_win_divisor,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "tcp_limit_output_bytes",
		.data		= &init_net.ipv4.sysctl_tcp_limit_output_bytes,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "tcp_challenge_ack_limit",
		.data		= &init_net.ipv4.sysctl_tcp_challenge_ack_limit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "tcp_tso_rtt_log",
		.data		= &init_net.ipv4.sysctl_tcp_tso_rtt_log,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
	},
	{
		.procname	= "tcp_min_rtt_wlen",
		.data		= &init_net.ipv4.sysctl_tcp_min_rtt_wlen,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &one_day_secs
	},
	{
		.procname	= "tcp_autocorking",
		.data		= &init_net.ipv4.sysctl_tcp_autocorking,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "tcp_invalid_ratelimit",
		.data		= &init_net.ipv4.sysctl_tcp_invalid_ratelimit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_ms_jiffies,
	},
	{
		.procname	= "tcp_pacing_ss_ratio",
		.data		= &init_net.ipv4.sysctl_tcp_pacing_ss_ratio,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_THOUSAND,
	},
	{
		.procname	= "tcp_pacing_ca_ratio",
		.data		= &init_net.ipv4.sysctl_tcp_pacing_ca_ratio,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_THOUSAND,
	},
	{
		.procname	= "tcp_wmem",
		.data		= &init_net.ipv4.sysctl_tcp_wmem,
		.maxlen		= sizeof(init_net.ipv4.sysctl_tcp_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "tcp_rmem",
		.data		= &init_net.ipv4.sysctl_tcp_rmem,
		.maxlen		= sizeof(init_net.ipv4.sysctl_tcp_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "tcp_comp_sack_delay_ns",
		.data		= &init_net.ipv4.sysctl_tcp_comp_sack_delay_ns,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "tcp_comp_sack_rtt_percent",
		.data		= &init_net.ipv4.sysctl_tcp_comp_sack_rtt_percent,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_ONE_THOUSAND,
	},
	{
		.procname	= "tcp_comp_sack_slack_ns",
		.data		= &init_net.ipv4.sysctl_tcp_comp_sack_slack_ns,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "tcp_comp_sack_nr",
		.data		= &init_net.ipv4.sysctl_tcp_comp_sack_nr,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "tcp_backlog_ack_defer",
		.data		= &init_net.ipv4.sysctl_tcp_backlog_ack_defer,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "tcp_ehash_entries",
		.data		= &init_net.ipv4.sysctl_tcp_child_ehash_entries,
		.mode		= 0444,
		.proc_handler	= proc_tcp_ehash_entries,
	},
	{
		.procname	= "tcp_child_ehash_entries",
		.data		= &init_net.ipv4.sysctl_tcp_child_ehash_entries,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &tcp_child_ehash_entries_max,
	},
	{
		.procname	= "udp_rmem_min",
		.data		= &init_net.ipv4.sysctl_udp_rmem_min,
		.maxlen		= sizeof(init_net.ipv4.sysctl_udp_rmem_min),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE
	},
	{
		.procname	= "udp_wmem_min",
		.data		= &init_net.ipv4.sysctl_udp_wmem_min,
		.maxlen		= sizeof(init_net.ipv4.sysctl_udp_wmem_min),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE
	},
	{
		.procname	= "fib_notify_on_flag_change",
		.data		= &init_net.ipv4.sysctl_fib_notify_on_flag_change,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	{
		.procname       = "tcp_plb_enabled",
		.data           = &init_net.ipv4.sysctl_tcp_plb_enabled,
		.maxlen         = sizeof(u8),
		.mode           = 0644,
		.proc_handler   = proc_dou8vec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "tcp_plb_idle_rehash_rounds",
		.data           = &init_net.ipv4.sysctl_tcp_plb_idle_rehash_rounds,
		.maxlen         = sizeof(u8),
		.mode           = 0644,
		.proc_handler   = proc_dou8vec_minmax,
		.extra2		= &tcp_plb_max_rounds,
	},
	{
		.procname       = "tcp_plb_rehash_rounds",
		.data           = &init_net.ipv4.sysctl_tcp_plb_rehash_rounds,
		.maxlen         = sizeof(u8),
		.mode           = 0644,
		.proc_handler   = proc_dou8vec_minmax,
		.extra2         = &tcp_plb_max_rounds,
	},
	{
		.procname       = "tcp_plb_suspend_rto_sec",
		.data           = &init_net.ipv4.sysctl_tcp_plb_suspend_rto_sec,
		.maxlen         = sizeof(u8),
		.mode           = 0644,
		.proc_handler   = proc_dou8vec_minmax,
	},
	{
		.procname       = "tcp_plb_cong_thresh",
		.data           = &init_net.ipv4.sysctl_tcp_plb_cong_thresh,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = &tcp_plb_max_cong_thresh,
	},
	{
		.procname	= "tcp_pingpong_thresh",
		.data		= &init_net.ipv4.sysctl_tcp_pingpong_thresh,
		.maxlen		= sizeof(u8),
		.mode		= 0644,
		.proc_handler	= proc_dou8vec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "tcp_rto_min_us",
		.data		= &init_net.ipv4.sysctl_tcp_rto_min_us,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "tcp_rto_max_ms",
		.data		= &init_net.ipv4.sysctl_tcp_rto_max_ms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE_THOUSAND,
		.extra2		= &tcp_rto_max_max,
	},
};

static __net_init int ipv4_sysctl_init_net(struct net *net)
{
	size_t table_size = ARRAY_SIZE(ipv4_net_table);
	struct ctl_table *table;

	table = ipv4_net_table;
	if (!net_eq(net, &init_net)) {
		int i;

		table = kmemdup(table, sizeof(ipv4_net_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;

		for (i = 0; i < table_size; i++) {
			if (table[i].data) {
				/* Update the variables to point into
				 * the current struct net
				 */
				table[i].data += (void *)net - (void *)&init_net;
			} else {
				/* Entries without data pointer are global;
				 * Make them read-only in non-init_net ns
				 */
				table[i].mode &= ~0222;
			}
		}
	}

	net->ipv4.ipv4_hdr = register_net_sysctl_sz(net, "net/ipv4", table,
						    table_size);
	if (!net->ipv4.ipv4_hdr)
		goto err_reg;


	proc_fib_multipath_hash_set_seed(net, 0);

	return 0;

err_ports:
	unregister_net_sysctl_table(net->ipv4.ipv4_hdr);
err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static __net_exit void ipv4_sysctl_exit_net(struct net *net)
{
	const struct ctl_table *table;

	table = net->ipv4.ipv4_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->ipv4.ipv4_hdr);
	kfree(table);
}

static __net_initdata struct pernet_operations ipv4_sysctl_ops = {
	.init = ipv4_sysctl_init_net,
	.exit = ipv4_sysctl_exit_net,
};

static __init int sysctl_ipv4_init(void)
{
	struct ctl_table_header *hdr;

	hdr = register_net_sysctl(&init_net, "net/ipv4", ipv4_table);
	if (!hdr)
		return -ENOMEM;

	proc_fib_multipath_hash_init_rand_seed();

	if (register_pernet_subsys(&ipv4_sysctl_ops)) {
		unregister_net_sysctl_table(hdr);
		return -ENOMEM;
	}

	return 0;
}

__initcall(sysctl_ipv4_init);
