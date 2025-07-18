/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _LINUX_RSTREASON_H
#define _LINUX_RSTREASON_H
#include <net/dropreason-core.h>
// uapi/linux/mptcp.h

#define DEFINE_RST_REASON(FN, FNe)	\
	FN(NOT_SPECIFIED)		\
	FN(NO_SOCKET)			\
	FN(TCP_INVALID_ACK_SEQUENCE)	\
	FN(TCP_RFC7323_PAWS)		\
	FN(TCP_TOO_OLD_ACK)		\
	FN(TCP_ACK_UNSENT_DATA)		\
	FN(TCP_FLAGS)			\
	FN(TCP_OLD_ACK)			\
	FN(TCP_ABORT_ON_DATA)		\
	FN(TCP_TIMEWAIT_SOCKET)		\
	FN(INVALID_SYN)			\
	FN(TCP_ABORT_ON_CLOSE)		\
	FN(TCP_ABORT_ON_LINGER)		\
	FN(TCP_ABORT_ON_MEMORY)		\
	FN(TCP_STATE)			\
	FN(TCP_KEEPALIVE_TIMEOUT)	\
	FN(TCP_DISCONNECT_WITH_DATA)	\
	FN(ERROR)			\
	FNe(MAX)

/**
 * enum sk_rst_reason - the reasons of socket reset
 *
 * The reasons of sk reset, which are used in TCP/MPTCP protocols.
 *
 * There are three parts in order:
 * 1) skb drop reasons: relying on drop reasons for such as passive reset
 * 2) independent reset reasons: such as active reset reasons
 * 3) reset reasons in MPTCP: only for MPTCP use
 */
enum sk_rst_reason {
	/* Refer to include/net/dropreason-core.h
	 * Rely on skb drop reasons because it indicates exactly why RST
	 * could happen.
	 */
	/** @SK_RST_REASON_NOT_SPECIFIED: reset reason is not specified */
	SK_RST_REASON_NOT_SPECIFIED,
	/** @SK_RST_REASON_NO_SOCKET: no valid socket that can be used */
	SK_RST_REASON_NO_SOCKET,
	/**
	 * @SK_RST_REASON_TCP_INVALID_ACK_SEQUENCE: Not acceptable ACK SEQ
	 * field because ack sequence is not in the window between snd_una
	 * and snd_nxt
	 */
	SK_RST_REASON_TCP_INVALID_ACK_SEQUENCE,
	/**
	 * @SK_RST_REASON_TCP_RFC7323_PAWS: PAWS check, corresponding to
	 * LINUX_MIB_PAWSESTABREJECTED, LINUX_MIB_PAWSACTIVEREJECTED
	 */
	SK_RST_REASON_TCP_RFC7323_PAWS,
	/** @SK_RST_REASON_TCP_TOO_OLD_ACK: TCP ACK is too old */
	SK_RST_REASON_TCP_TOO_OLD_ACK,
	/**
	 * @SK_RST_REASON_TCP_ACK_UNSENT_DATA: TCP ACK for data we haven't
	 * sent yet
	 */
	SK_RST_REASON_TCP_ACK_UNSENT_DATA,
	/** @SK_RST_REASON_TCP_FLAGS: TCP flags invalid */
	SK_RST_REASON_TCP_FLAGS,
	/** @SK_RST_REASON_TCP_OLD_ACK: TCP ACK is old, but in window */
	SK_RST_REASON_TCP_OLD_ACK,
	/**
	 * @SK_RST_REASON_TCP_ABORT_ON_DATA: abort on data
	 * corresponding to LINUX_MIB_TCPABORTONDATA
	 */
	SK_RST_REASON_TCP_ABORT_ON_DATA,

	/* Here start with the independent reasons */
	/** @SK_RST_REASON_TCP_TIMEWAIT_SOCKET: happen on the timewait socket */
	SK_RST_REASON_TCP_TIMEWAIT_SOCKET,
	/**
	 * @SK_RST_REASON_INVALID_SYN: receive bad syn packet
	 * RFC 793 says if the state is not CLOSED/LISTEN/SYN-SENT then
	 * "fourth, check the SYN bit,...If the SYN is in the window it is
	 * an error, send a reset"
	 */
	SK_RST_REASON_INVALID_SYN,
	/**
	 * @SK_RST_REASON_TCP_ABORT_ON_CLOSE: abort on close
	 * corresponding to LINUX_MIB_TCPABORTONCLOSE
	 */
	SK_RST_REASON_TCP_ABORT_ON_CLOSE,
	/**
	 * @SK_RST_REASON_TCP_ABORT_ON_LINGER: abort on linger
	 * corresponding to LINUX_MIB_TCPABORTONLINGER
	 */
	SK_RST_REASON_TCP_ABORT_ON_LINGER,
	/**
	 * @SK_RST_REASON_TCP_ABORT_ON_MEMORY: abort on memory
	 * corresponding to LINUX_MIB_TCPABORTONMEMORY
	 */
	SK_RST_REASON_TCP_ABORT_ON_MEMORY,
	/**
	 * @SK_RST_REASON_TCP_STATE: abort on tcp state
	 * Please see RFC 9293 for all possible reset conditions
	 */
	SK_RST_REASON_TCP_STATE,
	/**
	 * @SK_RST_REASON_TCP_KEEPALIVE_TIMEOUT: time to timeout
	 * When we have already run out of all the chances, which means
	 * keepalive timeout, we have to reset the connection
	 */
	SK_RST_REASON_TCP_KEEPALIVE_TIMEOUT,
	/**
	 * @SK_RST_REASON_TCP_DISCONNECT_WITH_DATA: disconnect when write
	 * queue is not empty
	 * It means user has written data into the write queue when doing
	 * disconnecting, so we have to send an RST.
	 */
	SK_RST_REASON_TCP_DISCONNECT_WITH_DATA,

	/** @SK_RST_REASON_ERROR: unexpected error happens */
	SK_RST_REASON_ERROR,

	/**
	 * @SK_RST_REASON_MAX: Maximum of socket reset reasons.
	 * It shouldn't be used as a real 'reason'.
	 */
	SK_RST_REASON_MAX,
};

/* Convert skb drop reasons to enum sk_rst_reason type */
static inline enum sk_rst_reason
sk_rst_convert_drop_reason(enum skb_drop_reason reason)
{
	switch (reason) {
	case SKB_DROP_REASON_NOT_SPECIFIED:
		return SK_RST_REASON_NOT_SPECIFIED;
	case SKB_DROP_REASON_NO_SOCKET:
		return SK_RST_REASON_NO_SOCKET;
	case SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE:
		return SK_RST_REASON_TCP_INVALID_ACK_SEQUENCE;
	case SKB_DROP_REASON_TCP_RFC7323_PAWS:
		return SK_RST_REASON_TCP_RFC7323_PAWS;
	case SKB_DROP_REASON_TCP_TOO_OLD_ACK:
		return SK_RST_REASON_TCP_TOO_OLD_ACK;
	case SKB_DROP_REASON_TCP_ACK_UNSENT_DATA:
		return SK_RST_REASON_TCP_ACK_UNSENT_DATA;
	case SKB_DROP_REASON_TCP_FLAGS:
		return SK_RST_REASON_TCP_FLAGS;
	case SKB_DROP_REASON_TCP_OLD_ACK:
		return SK_RST_REASON_TCP_OLD_ACK;
	case SKB_DROP_REASON_TCP_ABORT_ON_DATA:
		return SK_RST_REASON_TCP_ABORT_ON_DATA;
	default:
		/* If we don't have our own corresponding reason */
		return SK_RST_REASON_NOT_SPECIFIED;
	}
}
#endif
