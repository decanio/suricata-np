/* Copyright (C) 2011,2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 *  \defgroup Netmap run mode
 *
 *  @{
 */

/**
 * \file
 *
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Netmap acquisition support
 * 
 * Derrived in part from source code written by Luigi Rizzo.
 *
 */

#include "suricata-common.h"
#include "config.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tm-threads-common.h"
#include "conf.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-error.h"
#include "util-privs.h"
#include "util-optimize.h"
#include "util-checksum.h"
#include "util-ioctl.h"
#include "tmqh-packetpool.h"
#include "source-netmap.h"
#include "runmodes.h"

#ifdef HAVE_NETMAP

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

#if HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
#endif

#if HAVE_LINUX_IF_ARP_H
#include <linux/if_arp.h>
#endif

#if HAVE_LINUX_FILTER_H
#include <linux/filter.h>
#endif

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <net/netmap.h>
#include <net/netmap_user.h>

#endif /* HAVE_NETMAP */

extern uint8_t suricata_ctl_flags;
extern int max_pending_packets;

#ifndef HAVE_NETMAP

TmEcode NoNetmapSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveNetmapRegister (void) {
    tmm_modules[TMM_RECEIVENETMAP].name = "ReceiveNetmap";
    tmm_modules[TMM_RECEIVENETMAP].ThreadInit = NoNetmapSupportExit;
    tmm_modules[TMM_RECEIVENETMAP].Func = NULL;
    tmm_modules[TMM_RECEIVENETMAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENETMAP].cap_flags = 0;
    tmm_modules[TMM_RECEIVENETMAP].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeNetmap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeNetmapRegister (void) {
    tmm_modules[TMM_DECODENETMAP].name = "DecodeNetmap";
    tmm_modules[TMM_DECODENETMAP].ThreadInit = NoNetmapSupportExit;
    tmm_modules[TMM_DECODENETMAP].Func = NULL;
    tmm_modules[TMM_DECODENETMAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_DECODENETMAP].cap_flags = 0;
    tmm_modules[TMM_DECODENETMAP].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief this function prints an error message and exits.
 */
TmEcode NoNetmapSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_AF_PACKET,"Error creating thread %s: you do not have "
               "support for Netmap enabled, please recompile "
               "with --enable-af-packet", tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have Netmap support */

#define AFP_IFACE_NAME_LENGTH 48

#define NETMAP_STATE_DOWN 0
#define NETMAP_STATE_UP 1

#define NETMAP_RECONNECT_TIMEOUT 500000
#define NETMAP_DOWN_COUNTER_INTERVAL 40

#define POLL_TIMEOUT 100

#ifndef TP_STATUS_USER_BUSY
/* for new use latest bit available in tp_status */
#define TP_STATUS_USER_BUSY (1 << 31)
#endif

/** protect pfring_set_bpf_filter, as it is not thread safe */
static SCMutex netmap_bpf_set_filter_lock = PTHREAD_MUTEX_INITIALIZER;

enum {
    NETMAP_READ_OK,
    NETMAP_READ_FAILURE,
    NETMAP_FAILURE,
    NETMAP_KERNEL_DROP,
};

union thdr {
    struct tpacket2_hdr *h2;
    void *raw;
};

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct NetmapThreadVars_
{
    /* thread specific socket */
    int socket;
    /* handle state */
    unsigned char netmap_state;

    /* data link type for the thread */
    int datalink;
    int cooked;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;

    ThreadVars *tv;
    TmSlot *slot;

    uint8_t *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */

    char iface[NETMAP_IFACE_NAME_LENGTH];
    LiveDevice *livedev;
    int down_count;

    /* Filter */
    char *bpf_filter;

    /* socket buffer size */
    int buffer_size;
    int promisc;
    ChecksumValidationMode checksum_mode;

    /* IPS stuff */
    char out_iface[NETMAP_IFACE_NAME_LENGTH];
    NetmapPeer *mpeer;

    int flags;
#if 0
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;
#endif

    int cluster_id;
    int cluster_type;

    int threads;
    int copy_mode;

    /* Netmap stuff starts here */
    int fd;
    int ringid;
    char *mem;				/* userspace mmap address */
    uint16_t qfirst, qlast;		/* range of queues to scan */
    u_int memsize;
    u_int queueid;
    u_int begin, end;			/* first...last+1 rings to check */
    struct netmap_if *nifp;
    struct netmap_ring *tx, *rx;	/* shortcuts */

    uint32_t if_flags;
    uint32_t if_reqcap;
    uint32_t if_curcap;

#if 0
    struct tpacket_req req;
    unsigned int tp_hdrlen;
    unsigned int ring_buflen;
    char *ring_buf;
    char *frame_buf;
    unsigned int frame_offset;
    int ring_size;
#endif

} NetmapThreadVars;

TmEcode ReceiveNetmap(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveNetmapThreadInit(ThreadVars *, void *, void **);
void ReceiveNetmapThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveNetmapThreadDeinit(ThreadVars *, void *);
TmEcode ReceiveNetmapLoop(ThreadVars *tv, void *data, void *slot);

TmEcode DecodeNetmapThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeNetmap(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

TmEcode NetmapSetBPFFilter(NetmapThreadVars *ptv);
static int NetmapGetIfnumByDev(int fd, const char *ifname, int verbose);
#if 0
static int NetmapGetDevFlags(int fd, const char *ifname);
static int NetmapDerefSocket(NetmapPeer* peer);
static int NetmapRefSocket(NetmapPeer* peer);
#endif

/**
 * \brief Registration Function for RecieveNetmap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveNetmapRegister (void) {
    tmm_modules[TMM_RECEIVENETMAP].name = "ReceiveNetmap";
    tmm_modules[TMM_RECEIVENETMAP].ThreadInit = ReceiveNetmapThreadInit;
    tmm_modules[TMM_RECEIVENETMAP].Func = NULL;
    tmm_modules[TMM_RECEIVENETMAP].PktAcqLoop = ReceiveNetmapLoop;
    tmm_modules[TMM_RECEIVENETMAP].ThreadExitPrintStats = ReceiveNetmapThreadExitStats;
    tmm_modules[TMM_RECEIVENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENETMAP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENETMAP].flags = TM_FLAG_RECEIVE_TM;
}


/**
 *  \defgroup afppeers Netmap peers list
 *
 * AF_PACKET has an IPS mode were interface are peered: packet from
 * on interface are sent the peered interface and the other way. The ::NetmapPeer
 * list is maitaining the list of peers. Each ::NetmapPeer is storing the needed
 * information to be able to send packet on the interface.
 * A element of the list must not be destroyed during the run of Suricata as it
 * is used by ::Packet and other threads.
 *
 *  @{
 */

typedef struct NetmapPeersList_ {
    TAILQ_HEAD(, NetmapPeer_) peers; /**< Head of list of fragments. */
    int cnt;
    int peered;
    int turn; /**< Next value for initialisation order */
    SC_ATOMIC_DECLARE(int, reached); /**< Counter used to synchronize start */
} NetmapPeersList;

/**
 * \brief Update the peer.
 *
 * Update the NetmapPeer of a thread ie set new state, socket number
 * or iface index.
 *
 */
void NetmapPeerUpdate(NetmapThreadVars *ptv)
{
    if (ptv->mpeer == NULL) {
        return;
    }
    (void)SC_ATOMIC_SET(ptv->mpeer->if_idx, NetmapGetIfnumByDev(ptv->socket, ptv->iface, 0));
    //(void)SC_ATOMIC_SET(ptv->mpeer->socket, ptv->socket);
    (void)SC_ATOMIC_SET(ptv->mpeer->state, ptv->netmap_state);
}

/**
 * \brief Clean and free ressource used by an ::NetmapPeer
 */
void NetmapPeerClean(NetmapPeer *peer)
{
#if 0
    if (peer->flags & AFP_SOCK_PROTECT)
        SCMutexDestroy(&peer->sock_protect);
    SC_ATOMIC_DESTROY(peer->socket);
#endif
    SC_ATOMIC_DESTROY(peer->if_idx);
    SC_ATOMIC_DESTROY(peer->state);
    SCFree(peer);
}

NetmapPeersList peerslist;


/**
 * \brief Init the global list of ::NetmapPeer
 */
TmEcode NetmapPeersListInit()
{
    SCEnter();
    TAILQ_INIT(&peerslist.peers);
    peerslist.peered = 0;
    peerslist.cnt = 0;
    peerslist.turn = 0;
    SC_ATOMIC_INIT(peerslist.reached);
    (void) SC_ATOMIC_SET(peerslist.reached, 0);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Check that all ::NetmapPeer got a peer
 *
 * \retval TM_ECODE_FAILED if some threads are not peered or TM_ECODE_OK else.
 */
TmEcode NetmapPeersListCheck()
{
#define AFP_PEERS_MAX_TRY 4
#define AFP_PEERS_WAIT 20000
    int try = 0;
    SCEnter();
    while (try < AFP_PEERS_MAX_TRY) {
        if (peerslist.cnt != peerslist.peered) {
            usleep(AFP_PEERS_WAIT);
        } else {
            SCReturnInt(TM_ECODE_OK);
        }
        try++;
    }
    SCLogError(SC_ERR_AFP_CREATE, "Threads number not equals");
    SCReturnInt(TM_ECODE_FAILED);
}

/**
 * \brief Declare a new AFP thread to Netmap peers list.
 */
TmEcode NetmapPeersListAdd(NetmapThreadVars *ptv)
{
    SCEnter();
    NetmapPeer *peer = SCMalloc(sizeof(NetmapPeer));
    NetmapPeer *pitem;
    int mtu, out_mtu;

    if (unlikely(peer == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(peer, 0, sizeof(NetmapPeer));
#if 0
    SC_ATOMIC_INIT(peer->socket);
    SC_ATOMIC_INIT(peer->sock_usage);
#endif
    SC_ATOMIC_INIT(peer->if_idx);
    SC_ATOMIC_INIT(peer->state);
    peer->flags = ptv->flags;
    peer->turn = peerslist.turn++;

#if 0
    if (peer->flags & AFP_SOCK_PROTECT) {
        SCMutexInit(&peer->sock_protect, NULL);
    }

    (void)SC_ATOMIC_SET(peer->sock_usage, 0);
#endif
    (void)SC_ATOMIC_SET(peer->state, NETMAP_STATE_DOWN);
    strlcpy(peer->iface, ptv->iface, NETMAP_IFACE_NAME_LENGTH);
    ptv->mpeer = peer;
    /* add element to iface list */
    TAILQ_INSERT_TAIL(&peerslist.peers, peer, next);

    if (ptv->copy_mode != NETMAP_COPY_MODE_NONE) {
        peerslist.cnt++;

        /* Iter to find a peer */
        TAILQ_FOREACH(pitem, &peerslist.peers, next) {
            if (pitem->peer)
                continue;
            if (strcmp(pitem->iface, ptv->out_iface))
                continue;
            peer->peer = pitem;
            pitem->peer = peer;
            mtu = GetIfaceMTU(ptv->iface);
            out_mtu = GetIfaceMTU(ptv->out_iface);
            if (mtu != out_mtu) {
                SCLogError(SC_ERR_AFP_CREATE,
                        "MTU on %s (%d) and %s (%d) are not equal, "
                        "transmission of packets bigger than %d will fail.",
                        ptv->iface, mtu,
                        ptv->out_iface, out_mtu,
                        (out_mtu > mtu) ? mtu : out_mtu);
            }
            peerslist.peered += 2;
            break;
        }
    }

    NetmapPeerUpdate(ptv);

    SCReturnInt(TM_ECODE_OK);
}

int NetmapPeersListWaitTurn(NetmapPeer *peer)
{
    /* If turn is zero, we already have started threads once */
    if (peerslist.turn == 0)
        return 0;

    if (peer->turn == SC_ATOMIC_GET(peerslist.reached))
        return 0;
    return 1;
}

void NetmapPeersListReachedInc()
{
    if (peerslist.turn == 0)
        return;

    if (SC_ATOMIC_ADD(peerslist.reached, 1) == peerslist.turn) {
        SCLogInfo("All Netmap capture threads are running.");
        (void)SC_ATOMIC_SET(peerslist.reached, 0);
        /* Set turn to 0 to skip syncrhonization when ReceiveNetmapLoop is
         * restarted.
         */
        peerslist.turn = 0;
    }
}

/**
 * \brief Clean the global peers list.
 */
void NetmapPeersListClean()
{
    NetmapPeer *pitem;

    while ((pitem = TAILQ_FIRST(&peerslist.peers))) {
        TAILQ_REMOVE(&peerslist.peers, pitem, next);
        NetmapPeerClean(pitem);
    }
}

/**
 * @}
 */

/**
 * \brief Registration Function for DecodeNetmap.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeNetmapRegister (void) {
    tmm_modules[TMM_DECODENETMAP].name = "DecodeNetmap";
    tmm_modules[TMM_DECODENETMAP].ThreadInit = DecodeNetmapThreadInit;
    tmm_modules[TMM_DECODENETMAP].Func = DecodeNetmap;
    tmm_modules[TMM_DECODENETMAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENETMAP].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENETMAP].RegisterTests = NULL;
    tmm_modules[TMM_DECODENETMAP].cap_flags = 0;
    tmm_modules[TMM_DECODENETMAP].flags = TM_FLAG_DECODE_TM;
}


static int NetmapOpen(NetmapThreadVars *ptv, char *devname, int verbose);
#if 0
static int NetmapCreateSocket(NetmapThreadVars *ptv, char *devname, int verbose);
#endif

static inline void NetmapDumpCounters(NetmapThreadVars *ptv)
{
#ifdef PACKET_STATISTICS
    struct tpacket_stats kstats;
    socklen_t len = sizeof (struct tpacket_stats);
    if (getsockopt(ptv->socket, SOL_PACKET, PACKET_STATISTICS,
                &kstats, &len) > -1) {
        SCLogDebug("(%s) Kernel: Packets %" PRIu32 ", dropped %" PRIu32 "",
                ptv->tv->name,
                kstats.tp_packets, kstats.tp_drops);
#ifdef NOTYET
        SCPerfCounterAddUI64(ptv->capture_kernel_packets, ptv->tv->sc_perf_pca, kstats.tp_packets);
        SCPerfCounterAddUI64(ptv->capture_kernel_drops, ptv->tv->sc_perf_pca, kstats.tp_drops);
#endif
        (void) SC_ATOMIC_ADD(ptv->livedev->drop, kstats.tp_drops);
    }
#endif
}

#if 0
/**
 * \brief AF packet read function.
 *
 * This function fills
 * From here the packets are picked up by the DecodeNetmap thread.
 *
 * \param user pointer to NetmapThreadVars
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
int NetmapRead(NetmapThreadVars *ptv)
{
    Packet *p = NULL;
    /* XXX should try to use read that get directly to packet */
    int offset = 0;
    int caplen;
    struct sockaddr_ll from;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    union {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;
    unsigned char aux_checksum = 0;

    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags = 0;

    if (ptv->cooked)
        offset = SLL_HEADER_LEN;
    else
        offset = 0;
    iov.iov_len = ptv->datalen - offset;
    iov.iov_base = ptv->data + offset;

    caplen = recvmsg(ptv->socket, &msg, MSG_TRUNC);

    if (caplen < 0) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        SCReturnInt(NETMAP_READ_FAILURE);
    }

    p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnInt(NETMAP_FAILURE);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    /* get timestamp of packet via ioctl */
    if (ioctl(ptv->socket, SIOCGSTAMP, &p->ts) == -1) {
        SCLogWarning(SC_ERR_AFP_READ, "recvmsg failed with error code %" PRId32,
                errno);
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(NETMAP_READ_FAILURE);
    }

    ptv->pkts++;
    ptv->bytes += caplen + offset;
    (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
    p->livedev = ptv->livedev;

    /* add forged header */
    if (ptv->cooked) {
        SllHdr * hdrp = (SllHdr *)ptv->data;
        /* XXX this is minimalist, but this seems enough */
        hdrp->sll_protocol = from.sll_protocol;
    }

    p->datalink = ptv->datalink;
    SET_PKT_LEN(p, caplen + offset);
    if (PacketCopyData(p, ptv->data, GET_PKT_LEN(p)) == -1) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(NETMAP_FAILURE);
    }
    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
               GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    /* We only check for checksum disable */
    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ptv->livedev->ignore_checksum) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        } else if (ChecksumAutoModeCheck(ptv->pkts,
                                          SC_ATOMIC_GET(ptv->livedev->pkts),
                                          SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
            ptv->livedev->ignore_checksum = 1;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    } else {
        aux_checksum = 1;
    }

    /* List is NULL if we don't have activated auxiliary data */
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        struct tpacket_auxdata *aux;

        if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata)) ||
                cmsg->cmsg_level != SOL_PACKET ||
                cmsg->cmsg_type != PACKET_AUXDATA)
            continue;

        aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);

        if (aux_checksum && (aux->tp_status & TP_STATUS_CSUMNOTREADY)) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
        break;
    }

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ptv->tv, p);
        SCReturnInt(NETMAP_FAILURE);
    }
    SCReturnInt(NETMAP_READ_OK);
}
#endif

TmEcode NetmapWritePacket(Packet *p)
{
    struct sockaddr_ll socket_address;
    int socket;

    if (p->netmap_v.copy_mode == NETMAP_COPY_MODE_IPS) {
        if (p->action & ACTION_DROP) {
            return TM_ECODE_OK;
        }
    }

    if (SC_ATOMIC_GET(p->netmap_v.peer->state) == NETMAP_STATE_DOWN)
        return TM_ECODE_OK;

    if (p->ethh == NULL) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "Should have an Ethernet header");
        return TM_ECODE_FAILED;
    }

#ifdef NOTYET
    /* Index of the network device */
    socket_address.sll_ifindex = SC_ATOMIC_GET(p->netmap_v.peer->if_idx);
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    memcpy(socket_address.sll_addr, p->ethh, 6);

    /* Send packet, locking the socket if necessary */
    if (p->netmap_v.peer->flags & AFP_SOCK_PROTECT)
        SCMutexLock(&p->netmap_v.peer->sock_protect);
    socket = SC_ATOMIC_GET(p->netmap_v.peer->socket);
    if (sendto(socket, GET_PKT_DATA(p), GET_PKT_LEN(p), 0,
               (struct sockaddr*) &socket_address,
               sizeof(struct sockaddr_ll)) < 0) {
        SCLogWarning(SC_ERR_SOCKET, "Sending packet failed on socket %d: %s",
                  socket,
                  strerror(errno));
        if (p->netmap_v.peer->flags & AFP_SOCK_PROTECT)
            SCMutexUnlock(&p->netmap_v.peer->sock_protect);
        return TM_ECODE_FAILED;
    }
    if (p->netmap_v.peer->flags & AFP_SOCK_PROTECT)
        SCMutexUnlock(&p->netmap_v.peer->sock_protect);
#endif

    return TM_ECODE_OK;
}

TmEcode NetmapReleaseDataFromRing(ThreadVars *t, Packet *p)
{
    int ret = TM_ECODE_OK;
    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if ((p->netmap_v.copy_mode != NETMAP_COPY_MODE_NONE) && !PKT_IS_PSEUDOPKT(p)) {
        ret = NetmapWritePacket(p);
    }

#if 0
    if (NetmapDerefSocket(p->netmap_v.mpeer) == 0)
        goto cleanup;
#endif

    if (p->netmap_v.relptr) {
        union thdr h;
        h.raw = p->netmap_v.relptr;
        h.h2->tp_status = TP_STATUS_KERNEL;
    }

#if 0
cleanup:
#endif
    AFPV_CLEANUP(&p->netmap_v);
    return ret;
}

#if 0
/**
 * \brief AF packet read function for ring
 *
 * This function fills
 * From here the packets are picked up by the DecodeNetmap thread.
 *
 * \param user pointer to NetmapThreadVars
 * \retval TM_ECODE_FAILED on failure and TM_ECODE_OK on success
 */
int NetmapReadFromRing(NetmapThreadVars *ptv)
{
    Packet *p = NULL;
    union thdr h;
    struct sockaddr_ll *from;
    uint8_t emergency_flush = 0;
    int read_pkts = 0;
    int loop_start = -1;


    /* Loop till we have packets available */
    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            break;
        }

#if 0
        /* Read packet from ring */
        h.raw = (((union thdr **)ptv->frame_buf)[ptv->frame_offset]);
        if (h.raw == NULL) {
            SCReturnInt(NETMAP_FAILURE);
        }

        if (h.h2->tp_status == TP_STATUS_KERNEL) {
            if (read_pkts == 0) {
                if (loop_start == -1) {
                    loop_start = ptv->frame_offset;
                } else if (unlikely(loop_start == (int)ptv->frame_offset)) {
                    SCReturnInt(NETMAP_READ_OK);
                }
                if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
                    ptv->frame_offset = 0;
                }
                continue;
            }
            if ((emergency_flush) && (ptv->flags & AFP_EMERGENCY_MODE)) {
                SCReturnInt(NETMAP_KERNEL_DROP);
            } else {
                SCReturnInt(NETMAP_READ_OK);
            }
        }

        read_pkts++;
        loop_start = -1;

        /* Our packet is still used by suricata, we exit read loop to
         * gain some time */
        if (h.h2->tp_status & TP_STATUS_USER_BUSY) {
            SCReturnInt(NETMAP_READ_OK);
        }

        if ((ptv->flags & AFP_EMERGENCY_MODE) && (emergency_flush == 1)) {
            h.h2->tp_status = TP_STATUS_KERNEL;
            goto next_frame;
        }

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(NETMAP_FAILURE);
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);

        /* Suricata will treat packet so telling it is busy, this
         * status will be reset to 0 (ie TP_STATUS_KERNEL) in the release
         * function. */
        h.h2->tp_status |= TP_STATUS_USER_BUSY;

        from = (void *)h.raw + TPACKET_ALIGN(ptv->tp_hdrlen);

        ptv->pkts++;
        ptv->bytes += h.h2->tp_len;
        (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
        p->livedev = ptv->livedev;

        /* add forged header */
        if (ptv->cooked) {
            SllHdr * hdrp = (SllHdr *)ptv->data;
            /* XXX this is minimalist, but this seems enough */
            hdrp->sll_protocol = from->sll_protocol;
        }

        p->datalink = ptv->datalink;
        if (h.h2->tp_len > h.h2->tp_snaplen) {
            SCLogDebug("Packet length (%d) > snaplen (%d), truncating",
                    h.h2->tp_len, h.h2->tp_snaplen);
        }
        if (ptv->flags & AFP_ZERO_COPY) {
            if (PacketSetData(p, (unsigned char*)h.raw + h.h2->tp_mac, h.h2->tp_snaplen) == -1) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(NETMAP_FAILURE);
            } else {
                p->netmap_v.relptr = h.raw;
                p->ReleaseData = NetmapReleaseDataFromRing;
#if 0
                p->netmap_v.mpeer = ptv->mpeer;
                NetmapRefSocket(ptv->mpeer);
#endif

                p->netmap_v.copy_mode = ptv->copy_mode;
                if (p->netmap_v.copy_mode != AFP_COPY_MODE_NONE) {
#if 0
                    p->netmap_v.peer = ptv->mpeer->peer;
#endif
                } else {
                    p->netmap_v.peer = NULL;
                }
            }
        } else {
            if (PacketCopyData(p, (unsigned char*)h.raw + h.h2->tp_mac, h.h2->tp_snaplen) == -1) {
                TmqhOutputPacketpool(ptv->tv, p);
                SCReturnInt(NETMAP_FAILURE);
            }
        }
        /* Timestamp */
        p->ts.tv_sec = h.h2->tp_sec;
        p->ts.tv_usec = h.h2->tp_nsec/1000;
        SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
                GET_PKT_LEN(p), p, GET_PKT_DATA(p));

        /* We only check for checksum disable */
        if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
            if (ptv->livedev->ignore_checksum) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            } else if (ChecksumAutoModeCheck(ptv->pkts,
                        SC_ATOMIC_GET(ptv->livedev->pkts),
                        SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
                ptv->livedev->ignore_checksum = 1;
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
        } else {
            if (h.h2->tp_status & TP_STATUS_CSUMNOTREADY) {
                p->flags |= PKT_IGNORE_CHECKSUM;
            }
        }
        if (h.h2->tp_status & TP_STATUS_LOSING) {
            emergency_flush = 1;
            NetmapDumpCounters(ptv);
        }

        /* release frame if not in zero copy mode */
        if (!(ptv->flags &  AFP_ZERO_COPY)) {
            h.h2->tp_status = TP_STATUS_KERNEL;
        }

        if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
            h.h2->tp_status = TP_STATUS_KERNEL;
            if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
                ptv->frame_offset = 0;
            }
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(NETMAP_FAILURE);
        }

next_frame:
        if (++ptv->frame_offset >= ptv->req.tp_frame_nr) {
            ptv->frame_offset = 0;
            /* Get out of loop to be sure we will reach maintenance tasks */
            SCReturnInt(NETMAP_READ_OK);
        }
#endif
    }

    SCReturnInt(NETMAP_READ_OK);
}
#endif

#if 0
/**
 * \brief Reference socket
 *
 * \retval O in case of failure, 1 in case of success
 */
static int NetmapRefSocket(NetmapPeer* peer)
{
    if (unlikely(peer == NULL))
        return 0;

    (void)SC_ATOMIC_ADD(peer->sock_usage, 1);
    return 1;
}
#endif


#if 0
/**
 * \brief Dereference socket
 *
 * \retval 1 if socket is still alive, 0 if not
 */
static int NetmapDerefSocket(NetmapPeer* peer)
{
    if (SC_ATOMIC_SUB(peer->sock_usage, 1) == 0) {
        if (SC_ATOMIC_GET(peer->state) == NETMAP_STATE_DOWN) {
            SCLogInfo("Cleaning socket connected to '%s'", peer->iface);
            close(SC_ATOMIC_GET(peer->socket));
            return 0;
        }
    }
    return 1;
}
#endif

void NetmapSwitchState(NetmapThreadVars *ptv, int state)
{
    ptv->netmap_state = state;
    ptv->down_count = 0;

    NetmapPeerUpdate(ptv);

    /* Do cleaning if switching to down state */
    if (state == NETMAP_STATE_DOWN) {
#if 0
        if (ptv->frame_buf) {
            /* only used in reading phase, we can free it */
            SCFree(ptv->frame_buf);
            ptv->frame_buf = NULL;
        }
#endif
#if 0
        if (ptv->socket != -1) {
            /* we need to wait for all packets to return data */
            if (SC_ATOMIC_SUB(ptv->mpeer->sock_usage, 1) == 0) {
                SCLogInfo("Cleaning socket connected to '%s'", ptv->iface);
                close(ptv->socket);
                ptv->socket = -1;
            }
        }
#endif
    }
#if 0
    if (state == AFP_STATE_UP) {
         (void)SC_ATOMIC_SET(ptv->mpeer->sock_usage, 1);
    }
#endif
}

/**
 * \brief Try to reopen socket
 *
 * \retval 0 in case of success, negative if error occurs or a condition
 * is not met.
 */
static int NetmapTryReopen(NetmapThreadVars *ptv)
{
    int afp_activate_r;

    ptv->down_count++;


#if 0
    /* Don't reconnect till we have packet that did not release data */
    if (SC_ATOMIC_GET(ptv->mpeer->sock_usage) != 0) {
        return -1;
    }
#endif

#if 1
    afp_activate_r = NetmapOpen(ptv, ptv->iface, 0);
#else
    afp_activate_r = NetmapCreateSocket(ptv, ptv->iface, 0);
#endif
    if (afp_activate_r != 0) {
        if (ptv->down_count % NETMAP_DOWN_COUNTER_INTERVAL == 0) {
            SCLogWarning(SC_ERR_AFP_CREATE, "Can not open iface '%s'",
                         ptv->iface);
        }
        return afp_activate_r;
    }

    SCLogInfo("Interface '%s' is back", ptv->iface);
    return 0;
}

/**
 *  \brief Main AF_PACKET reading Loop function
 */
TmEcode ReceiveNetmapLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    Packet *p = NULL;
    uint16_t packet_q_len = 0;
    NetmapThreadVars *ptv = (NetmapThreadVars *)data;
    struct pollfd fds;
    int r, i;
    TmSlot *s = (TmSlot *)slot;
#if 0
    time_t last_dump = 0;
    struct timeval current_time;
#endif

    ptv->slot = s->slot_next;

    if (ptv->netmap_state == NETMAP_STATE_DOWN) {
        /* Wait for our turn, threads before us must have opened the socket */
        while (NetmapPeersListWaitTurn(ptv->mpeer)) {
            usleep(1000);
        }
        r = NetmapOpen(ptv, ptv->iface, 1);
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE, "Couldn't init Netmap fd");
        }
        NetmapPeersListReachedInc();
    }
    if (ptv->netmap_state == NETMAP_STATE_UP) {
        SCLogInfo("Thread %s using Netmap fd %d UP", tv->name, ptv->fd);
    }

    fds.fd = ptv->fd;
    fds.events = POLLIN;

    while (1) {
        /* Start by checking the state of our interface */
        if (unlikely(ptv->netmap_state == NETMAP_STATE_DOWN)) {
            int dbreak = 0;

            do {
                usleep(NETMAP_RECONNECT_TIMEOUT);
                if (suricata_ctl_flags != 0) {
                    dbreak = 1;
                    break;
                }
                r = NetmapTryReopen(ptv);
                fds.fd = ptv->socket;
            } while (r < 0);
            if (dbreak == 1)
                break;
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (unlikely(packet_q_len == 0)) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        r = poll(&fds, 1, POLL_TIMEOUT);

        if (suricata_ctl_flags != 0) {
            break;
        }

#if 1
	if (unlikely(r <= 0)) {
            SCPerfSyncCountersIfSignalled(tv, 0);
            continue;
	}

	for (i = ptv->qfirst; i < ptv->qlast; i++) {

            struct netmap_ring *ring = NETMAP_RXRING(ptv->nifp, i);
	    if (ring->avail > 0) {
                SCLogDebug("ring[%d]->avail: %" PRIu32 "", i, ring->avail);
	    }
            u_int cur = ring->cur;
            for ( ; ring->avail > 0 ; ring->avail--) {
                p = PacketGetFromQueueOrAlloc();
                if (unlikely(p == NULL)) {
                    break;
                }
                PKT_SET_SRC(p, PKT_SRC_WIRE);

                struct netmap_slot *slot = &ring->slot[cur];

                uint8_t *pkt = NETMAP_BUF(ring, slot->buf_idx);
                //int len = ring->slot[i].len;
                int len = slot->len;
                ptv->pkts++;
                ptv->bytes += len;
                SCLogDebug("Got a packet pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
                           len, p, pkt);
#ifdef DEBUG_PACKET_DUMPER
	        int j;
                for (j = 0; j < len; j++) {
                    printf("%02x ", pkt[j]);
                    if (((j+1)%16) ==0) printf("\n");
                }
                printf("\n");
#endif

                p->datalink = ptv->datalink;
                if (likely(PacketSetData(p, pkt, len) != -1)) {
                    /* TBD: need to do something more efficient than this */
                    gettimeofday(&p->ts, NULL);
                    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
                               GET_PKT_LEN(p), p, GET_PKT_DATA(p));
                    /* We only check for checksum disable */
                    if (ptv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
                        p->flags |= PKT_IGNORE_CHECKSUM;
                    } else if (ptv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
                        if (ptv->livedev->ignore_checksum) {
                            p->flags |= PKT_IGNORE_CHECKSUM;
                        } else if (ChecksumAutoModeCheck(ptv->pkts,
                                    SC_ATOMIC_GET(ptv->livedev->pkts),
                                    SC_ATOMIC_GET(ptv->livedev->invalid_checksums))) {
                            ptv->livedev->ignore_checksum = 1;
                            p->flags |= PKT_IGNORE_CHECKSUM;
                        }
                    } else {
                        p->flags |= PKT_IGNORE_CHECKSUM;
                    }

                    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) !=
                         TM_ECODE_OK) {
                        TmqhOutputPacketpool(ptv->tv, p);
                    }

                } else {
                    TmqhOutputPacketpool(ptv->tv, p);
                }
                (void) SC_ATOMIC_ADD(ptv->livedev->pkts, 1);
                ring->cur = NETMAP_RING_NEXT(ring, cur);        
            }
	}
        SCPerfSyncCountersIfSignalled(tv, 0);
#else

        if (r > 0 &&
                (fds.revents & (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))) {
            if (fds.revents & (POLLHUP | POLLRDHUP)) {
                NetmapSwitchState(ptv, NETMAP_STATE_DOWN);
                continue;
            } else if (fds.revents & POLLERR) {
                char c;
                /* Do a recv to get errno */
                if (recv(ptv->socket, &c, sizeof c, MSG_PEEK) != -1)
                    continue; /* what, no error? */
                SCLogError(SC_ERR_AFP_READ,
                           "Error reading data from iface '%s': (%d" PRIu32 ") %s",
                           ptv->iface, errno, strerror(errno));
                NetmapSwitchState(ptv, NETMAP_STATE_DOWN);
                continue;
            } else if (fds.revents & POLLNVAL) {
                SCLogError(SC_ERR_AFP_READ, "Invalid polling request");
                NetmapSwitchState(ptv, NETMAP_STATE_DOWN);
                continue;
            }
        } else if (r > 0) {
            if (ptv->flags & AFP_RING_MODE) {
                r = NetmapReadFromRing(ptv);
            } else {
                /* NetmapRead will call TmThreadsSlotProcessPkt on read packets */
                r = NetmapRead(ptv);
            }
            switch (r) {
                case NETMAP_READ_FAILURE:
                    /* NetmapRead in error: best to reset the socket */
                    SCLogError(SC_ERR_AFP_READ,
                           "AFPRead error reading data from iface '%s': (%d" PRIu32 ") %s",
                           ptv->iface, errno, strerror(errno));
                    NetmapSwitchState(ptv, NETMAP_STATE_DOWN);
                    continue;
                case NETMAP_FAILURE:
                    NetmapSwitchState(ptv, NETMAP_STATE_DOWN);
                    SCReturnInt(TM_ECODE_FAILED);
                    break;
                case NETMAP_READ_OK:
                    /* Trigger one dump of stats every second */
                    TimeGet(&current_time);
                    if (current_time.tv_sec != last_dump) {
                        NetmapDumpCounters(ptv);
                        last_dump = current_time.tv_sec;
                    }
                    break;
                case NETMAP_KERNEL_DROP:
                    NetmapDumpCounters(ptv);
                    break;
            }
        } else if ((r < 0) && (errno != EINTR)) {
            SCLogError(SC_ERR_AFP_READ, "Error reading data from iface '%s': (%d" PRIu32 ") %s",
                       ptv->iface,
                       errno, strerror(errno));
            NetmapSwitchState(ptv, NETMAP_STATE_DOWN);
            continue;
        }
        SCPerfSyncCountersIfSignalled(tv, 0);
#endif
    }

    SCReturnInt(TM_ECODE_OK);
}

#if 0
static int NetmapGetDevFlags(int fd, const char *ifname)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Unable to find type for iface \"%s\": %s",
                   ifname, strerror(errno));
        return -1;
    }

    return ifr.ifr_flags;
}
#endif


static int NetmapGetIfnumByDev(int fd, const char *ifname, int verbose)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
           if (verbose)
               SCLogError(SC_ERR_AFP_CREATE, "Unable to find iface %s: %s",
                          ifname, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

static int NetmapGetDevLinktype(int fd, const char *ifname)
{
#if 1
    return LINKTYPE_ETHERNET;
#else
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Unable to find type for iface \"%s\": %s",
                   ifname, strerror(errno));
        return -1;
    }

    switch (ifr.ifr_hwaddr.sa_family) {
        case ARPHRD_LOOPBACK:
            return LINKTYPE_ETHERNET;
        case ARPHRD_PPP:
            return LINKTYPE_RAW;
        default:
            return ifr.ifr_hwaddr.sa_family;
    }
#endif
}

#if 0
static int NetmapComputeRingParams(NetmapThreadVars *ptv, int order)
{
    /* Compute structure:
       Target is to store all pending packets
       with a size equal to MTU + auxdata
       And we keep a decent number of block

       To do so:
       Compute frame_size (aligned to be able to fit in block
       Check which block size we need. Blocksize is a 2^n * pagesize
       We then need to get order, big enough to have
       frame_size < block size
       Find number of frame per block (divide)
       Fill in packet_req

       Compute frame size:
       described in packet_mmap.txt
       dependant on snaplen (need to use a variable ?)
snaplen: MTU ?
tp_hdrlen determine_version in daq_afpacket
in V1:  sizeof(struct tpacket_hdr);
in V2: val in getsockopt(instance->fd, SOL_PACKET, PACKET_HDRLEN, &val, &len)
frame size: TPACKET_ALIGN(snaplen + TPACKET_ALIGN(TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll) + ETH_HLEN) - ETH_HLEN);

     */
#if 0
    int tp_hdrlen = sizeof(struct tpacket_hdr);
    int snaplen = default_packet_size;

    ptv->req.tp_frame_size = TPACKET_ALIGN(snaplen +TPACKET_ALIGN(TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll) + ETH_HLEN) - ETH_HLEN);
    ptv->req.tp_block_size = getpagesize() << order;
    int frames_per_block = ptv->req.tp_block_size / ptv->req.tp_frame_size;
    if (frames_per_block == 0) {
        SCLogInfo("frame size to big");
        return -1;
    }
    ptv->req.tp_frame_nr = ptv->ring_size;
    ptv->req.tp_block_nr = ptv->req.tp_frame_nr / frames_per_block + 1;
    /* exact division */
    ptv->req.tp_frame_nr = ptv->req.tp_block_nr * frames_per_block;
    SCLogInfo("AF_PACKET RX Ring params: block_size=%d block_nr=%d frame_size=%d frame_nr=%d",
              ptv->req.tp_block_size, ptv->req.tp_block_nr,
              ptv->req.tp_frame_size, ptv->req.tp_frame_nr);
#endif
    return 1;
}
#endif

static int NetmapOpen(NetmapThreadVars *ptv, char *devname, int verbose)
{
    int fd, err, l;
    struct nmreq req;

   
    ptv->fd = fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't open /dev/netmap, error %s", strerror(errno));
        goto error;
    }
    memset(&req, 0, sizeof(req));
    req.nr_version = NETMAP_API;
    strncpy(req.nr_name, ptv->iface, sizeof(req.nr_name));
    req.nr_ringid = ptv->ringid;
    err = ioctl(fd, NIOCGINFO, &req);
    if (err) {
        SCLogError(SC_ERR_AFP_CREATE, "Cannot get into on %s, error %s ver %d",
                   ptv->iface, strerror(errno), req.nr_version);
        goto error;
    }
    ptv->memsize = l = req.nr_memsize;
    SCLogInfo("memsize is %d MB", l>>20);
    err = ioctl(fd, NIOCREGIF, &req);
    if (err) {
        SCLogError(SC_ERR_AFP_CREATE, "Unable to register %s",
                   ptv->iface);
        goto error;
    }
    if (ptv->mem == NULL) {
        ptv->mem = mmap(0, l, PROT_WRITE|PROT_READ, MAP_SHARED, fd, 0);
        if (ptv->mem == MAP_FAILED) {
            SCLogError(SC_ERR_AFP_CREATE, "Unable to mmap %s, error %s",
                   ptv->iface, strerror(errno));
            ptv->mem = NULL;
            goto error;
        }
    }

    ptv->nifp = NETMAP_IF(ptv->mem, req.nr_offset);
    ptv->queueid = ptv->ringid;
    ptv->qfirst = 0;
    ptv->qlast = req.nr_rx_rings;
    if (ptv->ringid & NETMAP_SW_RING) {
        ptv->begin = req.nr_rx_rings;
        ptv->end = ptv->begin + 1;
        ptv->tx = NETMAP_TXRING(ptv->nifp, req.nr_tx_rings);
        ptv->rx = NETMAP_RXRING(ptv->nifp, req.nr_rx_rings);
    } else if (ptv->ringid & NETMAP_HW_RING) {
        SCLogInfo("XXX check multiple threads");
        ptv->begin = ptv->ringid & NETMAP_RING_MASK;
        ptv->end = ptv->begin + 1;
        ptv->tx = NETMAP_TXRING(ptv->nifp, ptv->begin);
        ptv->rx = NETMAP_RXRING(ptv->nifp, ptv->begin);
    } else {
        ptv->begin = 0;
        ptv->end = req.nr_rx_rings; /* XXX max of the two */
        ptv->tx = NETMAP_TXRING(ptv->nifp, 0);
        ptv->rx = NETMAP_RXRING(ptv->nifp, 0);
    }
    ptv->datalink = NetmapGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
    }

    /* Init is ok */
    NetmapSwitchState(ptv, NETMAP_STATE_UP);
    return (0);

error:
    close(ptv->fd);
    return -1;
}

#if 0
static int NetmapCreateSocket(NetmapThreadVars *ptv, char *devname, int verbose)
{
    int r;
    struct packet_mreq sock_params;
    struct sockaddr_ll bind_address;
    int order;
    unsigned int i;
    int if_idx;

    /* open socket */
    ptv->socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ptv->socket == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Couldn't create a AF_PACKET socket, error %s", strerror(errno));
        goto error;
    }
    if_idx = NetmapGetIfnumByDev(ptv->socket, devname, verbose);
    /* bind socket */
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = if_idx;
    if (bind_address.sll_ifindex == -1) {
        if (verbose)
            SCLogError(SC_ERR_AFP_CREATE, "Couldn't find iface %s", devname);
        goto socket_err;
    }



    if (ptv->promisc != 0) {
        /* Force promiscuous mode */
        memset(&sock_params, 0, sizeof(sock_params));
        sock_params.mr_type = PACKET_MR_PROMISC;
        sock_params.mr_ifindex = bind_address.sll_ifindex;
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP,(void *)&sock_params, sizeof(sock_params));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Couldn't switch iface %s to promiscuous, error %s",
                    devname, strerror(errno));
            goto frame_err;
        }
    }

    if (ptv->checksum_mode == CHECKSUM_VALIDATION_KERNEL) {
        int val = 1;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_AUXDATA, &val,
                    sizeof(val)) == -1 && errno != ENOPROTOOPT) {
            SCLogWarning(SC_ERR_NO_AF_PACKET,
                         "'kernel' checksum mode not supported, failling back to full mode.");
            ptv->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        }
    }

    /* set socket recv buffer size */
    if (ptv->buffer_size != 0) {
        /*
         * Set the socket buffer size to the specified value.
         */
        SCLogInfo("Setting AF_PACKET socket buffer to %d", ptv->buffer_size);
        if (setsockopt(ptv->socket, SOL_SOCKET, SO_RCVBUF,
                       &ptv->buffer_size,
                       sizeof(ptv->buffer_size)) == -1) {
            SCLogError(SC_ERR_AFP_CREATE,
                    "Couldn't set buffer size to %d on iface %s, error %s",
                    ptv->buffer_size, devname, strerror(errno));
            goto frame_err;
        }
    }

    r = bind(ptv->socket, (struct sockaddr *)&bind_address, sizeof(bind_address));
    if (r < 0) {
        if (verbose) {
            if (errno == ENETDOWN) {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Couldn't bind AF_PACKET socket, iface %s is down",
                        devname);
            } else {
                SCLogError(SC_ERR_AFP_CREATE,
                        "Couldn't bind AF_PACKET socket to iface %s, error %s",
                        devname, strerror(errno));
            }
        }
        goto frame_err;
    }

    int if_flags = NetmapGetDevFlags(ptv->socket, ptv->iface);
    if (if_flags == -1) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Can not acces to interface '%s'",
                    ptv->iface);
        }
        goto frame_err;
    }
    if ((if_flags & IFF_UP) == 0) {
        if (verbose) {
            SCLogError(SC_ERR_AFP_READ,
                    "Interface '%s' is down",
                    ptv->iface);
        }
        goto frame_err;
    }

    if (ptv->flags & AFP_RING_MODE) {
        int val = TPACKET_V2;
        unsigned int len = sizeof(val);
        if (getsockopt(ptv->socket, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0) {
            if (errno == ENOPROTOOPT) {
                SCLogError(SC_ERR_AFP_CREATE,
                           "Too old kernel giving up (need 2.6.27 at least)");
            }
            SCLogError(SC_ERR_AFP_CREATE, "Error when retrieving packet header len");
            goto socket_err;
        }
        ptv->tp_hdrlen = val;

        val = TPACKET_V2;
        if (setsockopt(ptv->socket, SOL_PACKET, PACKET_VERSION, &val,
                    sizeof(val)) < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Can't activate TPACKET_V2 on packet socket: %s",
                       strerror(errno));
            goto socket_err;
        }

        /* Allocate RX ring */
#define DEFAULT_ORDER 3
        for (order = DEFAULT_ORDER; order >= 0; order--) {
            if (NetmapComputeRingParams(ptv, order) != 1) {
                SCLogInfo("Ring parameter are incorrect. Please correct the devel");
            }

            r = setsockopt(ptv->socket, SOL_PACKET, PACKET_RX_RING, (void *) &ptv->req, sizeof(ptv->req));
            if (r < 0) {
                if (errno == ENOMEM) {
                    SCLogInfo("Memory issue with ring parameters. Retrying.");
                    continue;
                }
                SCLogError(SC_ERR_MEM_ALLOC,
                        "Unable to allocate RX Ring for iface %s: (%d) %s",
                        devname,
                        errno,
                        strerror(errno));
                goto socket_err;
            } else {
                break;
            }
        }

        if (order < 0) {
            SCLogError(SC_ERR_MEM_ALLOC,
                    "Unable to allocate RX Ring for iface %s (order 0 failed)",
                    devname);
            goto socket_err;
        }

        /* Allocate the Ring */
        ptv->ring_buflen = ptv->req.tp_block_nr * ptv->req.tp_block_size;
        ptv->ring_buf = mmap(0, ptv->ring_buflen, PROT_READ|PROT_WRITE,
                MAP_SHARED, ptv->socket, 0);
        if (ptv->ring_buf == MAP_FAILED) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to mmap");
            goto socket_err;
        }
        /* allocate a ring for each frame header pointer*/
        ptv->frame_buf = SCMalloc(ptv->req.tp_frame_nr * sizeof (union thdr *));
        if (ptv->frame_buf == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate frame buf");
            goto mmap_err;
        }
        memset(ptv->frame_buf, 0, ptv->req.tp_frame_nr * sizeof (union thdr *));
        /* fill the header ring with proper frame ptr*/
        ptv->frame_offset = 0;
        for (i = 0; i < ptv->req.tp_block_nr; ++i) {
            void *base = &ptv->ring_buf[i * ptv->req.tp_block_size];
            unsigned int j;
            for (j = 0; j < ptv->req.tp_block_size / ptv->req.tp_frame_size; ++j, ++ptv->frame_offset) {
                (((union thdr **)ptv->frame_buf)[ptv->frame_offset]) = base;
                base += ptv->req.tp_frame_size;
            }
        }
        ptv->frame_offset = 0;
    }

    SCLogInfo("Using interface '%s' via socket %d", (char *)devname, ptv->socket);

#ifdef HAVE_PACKET_FANOUT
    /* add binded socket to fanout group */
    if (ptv->threads > 1) {
        uint32_t option = 0;
        uint16_t mode = ptv->cluster_type;
        uint16_t id = ptv->cluster_id;
        option = (mode << 16) | (id & 0xffff);
        r = setsockopt(ptv->socket, SOL_PACKET, PACKET_FANOUT,(void *)&option, sizeof(option));
        if (r < 0) {
            SCLogError(SC_ERR_AFP_CREATE,
                       "Coudn't set fanout mode, error %s",
                       strerror(errno));
            goto frame_err;
        }
    }
#endif

    ptv->datalink = NetmapGetDevLinktype(ptv->socket, ptv->iface);
    switch (ptv->datalink) {
        case ARPHRD_PPP:
        case ARPHRD_ATM:
            ptv->cooked = 1;
    }

    TmEcode rc;
    rc = NetmapSetBPFFilter(ptv);
    if (rc == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_AFP_CREATE, "Set Netmap bpf filter \"%s\" failed.", ptv->bpf_filter);
        goto frame_err;
    }

    /* Init is ok */
    NetmapSwitchState(ptv, NETMAP_STATE_UP);
    return 0;

frame_err:
    if (ptv->frame_buf)
        SCFree(ptv->frame_buf);
mmap_err:
    /* Packet mmap does the cleaning when socket is closed */
socket_err:
    close(ptv->socket);
    ptv->socket = -1;
error:
    return -1;
}
#endif

TmEcode NetmapSetBPFFilter(NetmapThreadVars *ptv)
{
    struct bpf_program filter;
    struct sock_fprog  fcode;
    int rc;

    if (!ptv->bpf_filter)
        return TM_ECODE_OK;

    SCMutexLock(&netmap_bpf_set_filter_lock);

    SCLogInfo("Using BPF '%s' on iface '%s'",
              ptv->bpf_filter,
              ptv->iface);
    if (pcap_compile_nopcap(default_packet_size,  /* snaplen_arg */
                ptv->datalink,    /* linktype_arg */
                &filter,       /* program */
                ptv->bpf_filter, /* const char *buf */
                0,             /* optimize */
                0              /* mask */
                ) == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Filter compilation failed.");
        SCMutexUnlock(&netmap_bpf_set_filter_lock);
        return TM_ECODE_FAILED;
    }
    SCMutexUnlock(&netmap_bpf_set_filter_lock);

    if (filter.bf_insns == NULL) {
        SCLogError(SC_ERR_AFP_CREATE, "Filter badly setup.");
        return TM_ECODE_FAILED;
    }

    fcode.len    = filter.bf_len;
    fcode.filter = (struct sock_filter*)filter.bf_insns;

    rc = setsockopt(ptv->socket, SOL_SOCKET, SO_ATTACH_FILTER, &fcode, sizeof(fcode));

    if(rc == -1) {
        SCLogError(SC_ERR_AFP_CREATE, "Failed to attach filter: %s", strerror(errno));
        return TM_ECODE_FAILED;
    }

    SCMutexUnlock(&netmap_bpf_set_filter_lock);
    return TM_ECODE_OK;
}


/**
 * \brief Init function for ReceiveNetmap.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with NetmapThreadVars
 *
 * \todo Create a general Netmap setup function.
 */
TmEcode ReceiveNetmapThreadInit(ThreadVars *tv, void *initdata, void **data) {
    SCEnter();
    NetmapIfaceConfig *netmapconfig = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    NetmapThreadVars *ptv = SCMalloc(sizeof(NetmapThreadVars));
    if (unlikely(ptv == NULL)) {
        netmapconfig->DerefFunc(netmapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }
    memset(ptv, 0, sizeof(NetmapThreadVars));

    ptv->tv = tv;
    ptv->cooked = 0;

    strlcpy(ptv->iface, netmapconfig->iface, NETMAP_IFACE_NAME_LENGTH);
    ptv->iface[AFP_IFACE_NAME_LENGTH - 1]= '\0';

    ptv->livedev = LiveGetDevice(ptv->iface);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

#ifdef NOTYET
    ptv->buffer_size = afpconfig->buffer_size;
    ptv->ring_size = afpconfig->ring_size;
#endif

    ptv->promisc = netmapconfig->promisc;
    ptv->checksum_mode = netmapconfig->checksum_mode;
    ptv->bpf_filter = NULL;

    ptv->threads = 1;
#ifdef NOTYET
#ifdef HAVE_PACKET_FANOUT
    ptv->cluster_type = PACKET_FANOUT_LB;
    ptv->cluster_id = 1;
    /* We only set cluster info if the number of reader threads is greater than 1 */
    if (netmapconfig->threads > 1) {
            ptv->cluster_id = netmapconfig->cluster_id;
            ptv->cluster_type = netmapconfig->cluster_type;
            ptv->threads = netmapconfig->threads;
    }
#endif
#endif
    ptv->flags = netmapconfig->flags;

    if (netmapconfig->bpf_filter) {
        ptv->bpf_filter = netmapconfig->bpf_filter;
    }

#ifdef NOTYET
#ifdef PACKET_STATISTICS
    ptv->capture_kernel_packets = SCPerfTVRegisterCounter("capture.kernel_packets",
            ptv->tv,
            SC_PERF_TYPE_UINT64,
            "NULL");
    ptv->capture_kernel_drops = SCPerfTVRegisterCounter("capture.kernel_drops",
            ptv->tv,
            SC_PERF_TYPE_UINT64,
            "NULL");
#endif
#endif

    char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("workers", active_runmode)) {
        ptv->flags |= AFP_ZERO_COPY;
        SCLogInfo("Enabling zero copy mode");
    } else {
        /* If we are using copy mode we need a lock */
        ptv->flags |= AFP_SOCK_PROTECT;
    }

#ifdef NOTYET
    /* If we are in RING mode, then we can use ZERO copy
     * by using the data release mechanism */
    if (ptv->flags & AFP_RING_MODE) {
        ptv->flags |= AFP_ZERO_COPY;
        SCLogInfo("Enabling zero copy mode by using data release call");
    }
#endif

    ptv->copy_mode = netmapconfig->copy_mode;
    if (ptv->copy_mode != NETMAP_COPY_MODE_NONE) {
        strlcpy(ptv->out_iface, netmapconfig->out_iface, NETMAP_IFACE_NAME_LENGTH);
        ptv->out_iface[NETMAP_IFACE_NAME_LENGTH - 1]= '\0';
        /* Warn about BPF filter consequence */
        if (ptv->bpf_filter) {
            SCLogWarning(SC_WARN_UNCOMMON, "Enabling a BPF filter in IPS mode result"
                      " in dropping all non matching packets.");
        }
    }

    if (NetmapPeersListAdd(ptv) == TM_ECODE_FAILED) {
        SCFree(ptv);
        netmapconfig->DerefFunc(netmapconfig);
        SCReturnInt(TM_ECODE_FAILED);
    }

#define T_DATA_SIZE 70000
    ptv->data = SCMalloc(T_DATA_SIZE);
    if (ptv->data == NULL) {
        netmapconfig->DerefFunc(netmapconfig);
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }
    ptv->datalen = T_DATA_SIZE;
#undef T_DATA_SIZE

    *data = (void *)ptv;

    netmapconfig->DerefFunc(netmapconfig);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetmapThreadVars for ptv
 */
void ReceiveNetmapThreadExitStats(ThreadVars *tv, void *data) {
    SCEnter();
    NetmapThreadVars *ptv = (NetmapThreadVars *)data;

#ifdef NOTYET
#ifdef PACKET_STATISTICS
    NetmapDumpCounters(ptv);
    SCLogInfo("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 "",
            tv->name,
            (uint64_t) SCPerfGetLocalCounterValue(ptv->capture_kernel_packets, tv->sc_perf_pca),
            (uint64_t) SCPerfGetLocalCounterValue(ptv->capture_kernel_drops, tv->sc_perf_pca));
#endif
#endif

    SCLogInfo("(%s) Packets %" PRIu32 ", bytes %" PRIu64 "", tv->name, ptv->pkts, ptv->bytes);
}

/**
 * \brief DeInit function closes af packet socket at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into NetmapThreadVars for ptv
 */
TmEcode ReceiveNetmapThreadDeinit(ThreadVars *tv, void *data) {
    NetmapThreadVars *ptv = (NetmapThreadVars *)data;

    NetmapSwitchState(ptv, NETMAP_STATE_DOWN);

    if (ptv->data != NULL) {
        SCFree(ptv->data);
        ptv->data = NULL;
    }
    ptv->datalen = 0;

    ptv->bpf_filter = NULL;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeNetmap reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into NetmapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode DecodeNetmap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (GET_PKT_LEN(p) * 8)/1000000.0);
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p,GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_RAW:
            DecodeRaw(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodeNetmap", p->datalink);
            break;
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeNetmapThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_NETMAP */
/* eof */
/**
 * @}
 */
