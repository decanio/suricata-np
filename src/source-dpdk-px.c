/* Copyright (C) 2011-2016 Open Information Security Foundation
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
*  \defgroup DPDK running mode
*
*  @{
*/

/**
* \file
*
* \author Tom DeCanio <decanio.tom@gmail.com>
*
* DPDK acquisition support
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
#include "util-host-info.h"
#include "util-print.h"
#include "tmqh-packetpool.h"
#include "source-dpdk-px.h"
#include "runmodes.h"

#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#include "util-cuda-handlers.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-cuda-vars.h"

#endif /* __SC_CUDA_SUPPORT__ */

#ifdef HAVE_DPDK
#include <rte_config.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#endif /* HAVE_DPDK */

#include "util-ioctl.h"

#define PRINT

extern intmax_t max_pending_packets;

#ifndef HAVE_DPDK

TmEcode NoDPDKSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveDPDKRegister (void)
{
    tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
    tmm_modules[TMM_RECEIVEDPDK].ThreadInit = NoDPDKSupportExit;
    tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEDPDK].cap_flags = 0;
    tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
}

/**
* \brief Registration Function for DecodeDPDK.
* \todo Unit tests are needed for this module.
*/
void TmModuleDecodeDPDKRegister (void)
{
    tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
    tmm_modules[TMM_DECODEDPDK].ThreadInit = NoDPDKSupportExit;
    tmm_modules[TMM_DECODEDPDK].Func = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEDPDK].RegisterTests = NULL;
    tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
    tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
}

/**
* \brief this function prints an error message and exits.
*/
TmEcode NoDPDKSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NO_DPDK,"Error creating thread %s: you do not have "
            "support for netmap enabled, please recompile "
            "with --enable-netmap", tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have DPDK support */

#define max(a, b) (((a) > (b)) ? (a) : (b))

#define POLL_TIMEOUT 100

#if defined(__linux__)
#define POLL_EVENTS (POLLHUP|POLLRDHUP|POLLERR|POLLNVAL)

#ifndef IFF_PPROMISC
#define IFF_PPROMISC IFF_PROMISC
#endif

#else
#define POLL_EVENTS (POLLHUP|POLLERR|POLLNVAL)
#endif

enum {
    DPDK_OK,
    DPDK_FAILURE,
};

enum {
    DPDK_FLAG_ZERO_COPY = 1,
};

SC_ATOMIC_DECLARE(unsigned int, threads_run);

/* TBD: need to move these */
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define MBUF_CACHE_SIZE 512

/*
 * When doing reads from the NIC or the client queues,
 * use this batch size
 */
#define PACKET_READ_SIZE 32

/**
 * \brief DPDK device instance.
 */
typedef struct DPDKDevice_
{
    uint8_t port_id;
    struct rte_ring *rx_ring;
    struct rte_ring *rtn_ring;
    struct rte_mempool *mp;
    SC_ATOMIC_DECLARE(unsigned int, threads_run);
    TAILQ_ENTRY(DPDKDevice_) next;
} DPDKDevice;

/**
 * \brief Module thread local variables.
 */
typedef struct DPDKThreadVars_
{
    /* receive inteface */
    DPDKDevice *ifsrc;

    /* dst interface for IPS mode */
    DPDKDevice *ifdst;

    int threads;
    int thread_idx;
    int flags;

    /* internal shit */
    TmSlot *slot;
    ThreadVars *tv;
    LiveDevice *livedev;

    /* copy from config */
    unsigned num_mbufs;
    int rte_ring_mode;
    int copy_mode;
    ChecksumValidationMode checksum_mode;

    /* counters */
    uint64_t pkts;
    uint64_t bytes;
    uint64_t drops;
    uint16_t capture_kernel_packets;
    uint16_t capture_kernel_drops;

} DPDKThreadVars;

/**
 * \brief DPDKDumpCounters
 * \param ntv
 */
static inline void DPDKDumpCounters(DPDKThreadVars *ntv)
{
    StatsAddUI64(ntv->tv, ntv->capture_kernel_packets, ntv->pkts);
    StatsAddUI64(ntv->tv, ntv->capture_kernel_drops, ntv->drops);
    (void) SC_ATOMIC_ADD(ntv->livedev->drop, ntv->drops);
    (void) SC_ATOMIC_ADD(ntv->livedev->pkts, ntv->pkts);
    ntv->drops = 0;
    ntv->pkts = 0;
}

/**
 * \brief Init function for ReceiveDPDK.
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the interface passed from the user
 * \param data pointer gets populated with DPDKThreadVars
 */
static TmEcode ReceiveDPDKThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DPDKIfaceConfig *aconf = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    DPDKThreadVars *ntv = SCMalloc(sizeof(*ntv));
    if (unlikely(ntv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error;
    }
    memset(ntv, 0, sizeof(*ntv));

    ntv->tv = tv;
    ntv->checksum_mode = aconf->in.checksum_mode;
    ntv->rte_ring_mode = aconf->in.rte_ring_mode;
    ntv->num_mbufs = aconf->in.num_mbufs;
    ntv->copy_mode = aconf->in.copy_mode;
    ntv->threads = aconf->in.threads;
    ntv->thread_idx = SC_ATOMIC_ADD(threads_run, 1) - 1;

    ntv->livedev = LiveGetDevice(aconf->iface_name);
    if (ntv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        goto error_ntv;
    }

    ntv->ifsrc = SCMalloc(sizeof(*ntv->ifsrc));
    if (unlikely(ntv->ifsrc == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed");
        goto error_ntv;
    }
    memset(ntv->ifsrc, 0, sizeof(*ntv->ifsrc));

    if (ntv->rte_ring_mode == 0) {
        /* iface_name is really a DPDK port number */
        ntv->ifsrc->port_id = atoi(aconf->iface_name);
        if (ntv->thread_idx == 0) {
            /* for port configuration all features are off by default */
            const struct rte_eth_conf port_conf = {
                    .rxmode = {
                            .mq_mode = ETH_MQ_RX_RSS
                    }
            };
            int retval;

            /* initialize the mbuf pools */
            ntv->ifsrc->mp = rte_pktmbuf_pool_create(PKTMBUF_POOL_NAME,
                                                     ntv->num_mbufs,
                                                     MBUF_CACHE_SIZE, 0,
                                                     RTE_MBUF_DEFAULT_BUF_SIZE,
                                                     rte_socket_id());

            uint8_t count = rte_eth_dev_count();
            SCLogInfo("Found %d ethernet interfaces", count);

            retval = rte_eth_dev_configure(ntv->ifsrc->port_id,
                                           ntv->threads,
                                           ntv->threads,
                                           &port_conf);
            if (retval != 0) {
                SCLogError(SC_ERR_INVALID_VALUE, "Unable to configure DPDK port %x", ntv->ifsrc->port_id);
                goto error_src;
            }
        }
    } else {
        char ringname[DPDK_IFACE_NAME_LENGTH];

        snprintf(ringname, sizeof(ringname)-1, aconf->in.rx_ring, ntv->thread_idx);
        ntv->ifsrc->rx_ring = rte_ring_lookup(ringname);
        if (ntv->ifsrc->rx_ring == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Unable to find DPDK ring");
            goto error_src;
        }

        snprintf(ringname, sizeof(ringname)-1, aconf->in.rtn_ring, ntv->thread_idx);
        ntv->ifsrc->rtn_ring = rte_ring_lookup(ringname);
        if (ntv->ifsrc->rtn_ring == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Unable to find DPDK ring");
            goto error_src;
        }

        ntv->ifsrc->mp = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (ntv->ifsrc->mp == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Cannon get DPDK mempool for mbufs");
            goto error_src;
        }
    }

    SCLogDebug("DPDK: %s thread:%d rings:%d-%d", aconf->iface_name,
               ntv->thread_idx, ntv->src_ring_from, ntv->src_ring_to);

    /* basic counters */
    ntv->capture_kernel_packets = StatsRegisterCounter("capture.kernel_packets",
            ntv->tv);
    ntv->capture_kernel_drops = StatsRegisterCounter("capture.kernel_drops",
            ntv->tv);

    /* enable zero-copy mode for workers runmode */
    ntv->flags |= DPDK_FLAG_ZERO_COPY;

    *data = (void *)ntv;
    aconf->DerefFunc(aconf);
    SCReturnInt(TM_ECODE_OK);

error_src:
    if (ntv->ifsrc)
        SCFree(ntv->ifsrc);
error_ntv:
    SCFree(ntv);
error:
    aconf->DerefFunc(aconf);
    SCReturnInt(TM_ECODE_FAILED);
}

/**
 * \brief Packet release routine.
 * \param p Packet.
 */
static void DPDKReleasePacket(Packet *p)
{
    DPDKThreadVars *ntv = (DPDKThreadVars *)p->dpdk_v.ntv;

    /* Need to be in copy mode and need to detect early release
       where Ethernet header could not be set (and pseudo packet) */
    if (!PKT_IS_PSEUDOPKT(p)) {
        rte_ring_enqueue(ntv->ifsrc->rtn_ring, p->dpdk_v.m);
    }

    PacketFreeOrRelease(p);
}

/**
 * \brief Read packets from ring and pass them further.
 * \param ntv Thread local variables.
 * \param ring_id Ring id to read.
 */
static int DPDKPacketInput(DPDKThreadVars *ntv, struct rte_mbuf *m)
{
    SCEnter();
    uint32_t pkt_len = m->pkt_len;
    uint8_t *pkt_data = rte_pktmbuf_mtod(m, uint8_t *);

#ifdef PRINT
    static unsigned long long pcap_cnt = 0;
    printf("--------------- (thread: %u pcap_cnt: %llu)\n", ntv->thread_idx, ++pcap_cnt);
    PrintRawDataFp(stdout, pkt_data, pkt_len);
    printf("---------------\n");
#endif
    Packet *p = PacketPoolGetPacket();
    if (unlikely(p == NULL)) {
        SCReturnInt(DPDK_FAILURE);
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->livedev = ntv->livedev;
    p->datalink = LINKTYPE_ETHERNET;
    /* TBD: we have to do better than this */
    gettimeofday(&p->ts, NULL);
    ntv->pkts++;
    ntv->bytes += m->pkt_len;

    /* checksum validation */
    if (ntv->checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (ntv->checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ntv->livedev->ignore_checksum) {
            p->flags |= PKT_IGNORE_CHECKSUM;
        } else if (ChecksumAutoModeCheck(ntv->pkts,
                    SC_ATOMIC_GET(ntv->livedev->pkts),
                    SC_ATOMIC_GET(ntv->livedev->invalid_checksums))) {
            ntv->livedev->ignore_checksum = 1;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }

    if (ntv->flags & DPDK_FLAG_ZERO_COPY) {
        if (PacketSetData(p, pkt_data, pkt_len) == -1) {
            TmqhOutputPacketpool(ntv->tv, p);
            SCReturnInt(DPDK_FAILURE);
        }
    } else {
        if (PacketCopyData(p, pkt_data, pkt_len) == -1) {
            TmqhOutputPacketpool(ntv->tv, p);
            SCReturnInt(DPDK_FAILURE);
        }
    }

    p->ReleasePacket = DPDKReleasePacket;
    p->dpdk_v.ntv = ntv;
    p->dpdk_v.m = m;
    SCLogDebug("pktlen: %" PRIu32 " (pkt %p, pkt data %p)",
               GET_PKT_LEN(p), p, GET_PKT_DATA(p));

    if (TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK) {
        TmqhOutputPacketpool(ntv->tv, p);
        SCReturnInt(DPDK_FAILURE);
    }

    SCReturnInt(DPDK_OK);
}

/**
 *  \brief Main netmap reading loop function
 */
static TmEcode ReceiveDPDKLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    TmSlot *s = (TmSlot *)slot;
    DPDKThreadVars *ntv = (DPDKThreadVars *)data;
    struct rte_mbuf *m;

    ntv->slot = s->slot_next;

    if (ntv->rte_ring_mode == 0) {
        uint8_t port_id = ntv->ifsrc->port_id;
        uint16_t queue_id = ntv->thread_idx;

        /* consume packets from ethernet interface */
        for (;;) {
            struct rte_mbuf *buf[PACKET_READ_SIZE];
            uint16_t rx_count;
            uint16_t i;

            if (suricata_ctl_flags != 0) {
                break;
            }

            rx_count = rte_eth_rx_burst(port_id, queue_id, buf, PACKET_READ_SIZE);

            for (i = 0; i < rx_count; i++) {
                DPDKPacketInput(ntv, buf[i]);
            }

            DPDKDumpCounters(ntv);
            StatsSyncCountersIfSignalled(tv);
        }
                
    } else {
        struct rte_ring *rx_ring = ntv->ifsrc->rx_ring;

        /* consume packets from rte_ring */
        for(;;) {
            if (suricata_ctl_flags != 0) {
                break;
            }

            /* make sure we have at least one packet in the packet pool,
             * to prevent us from alloc'ing packets at line rate */
            PacketPoolWait();

            if (rte_ring_dequeue(rx_ring, (void *)&m) == 0) {
                DPDKPacketInput(ntv, m);
            }

            DPDKDumpCounters(ntv);
            StatsSyncCountersIfSignalled(tv);
        }
    }

    StatsSyncCountersIfSignalled(tv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DPDKThreadVars for ntv
 */
static void ReceiveDPDKThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    DPDKThreadVars *ntv = (DPDKThreadVars *)data;

    DPDKDumpCounters(ntv);
    SCLogPerf("(%s) Kernel: Packets %" PRIu64 ", dropped %" PRIu64 ", bytes %" PRIu64 "",
              tv->name,
              StatsGetLocalCounterValue(tv, ntv->capture_kernel_packets),
              StatsGetLocalCounterValue(tv, ntv->capture_kernel_drops),
              ntv->bytes);
}

/**
 * \brief
 * \param tv
 * \param data Pointer to DPDKThreadVars.
 */
static TmEcode ReceiveDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Prepare netmap decode thread.
 * \param tv Thread local avariables.
 * \param initdata Thread config.
 * \param data Pointer to DecodeThreadVars placed here.
 */
static TmEcode DecodeDPDKThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

#ifdef __SC_CUDA_SUPPORT__
    if (CudaThreadVarsInit(&dtv->cuda_vars) < 0)
        SCReturnInt(TM_ECODE_FAILED);
#endif

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeDPDK reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into DPDKThreadVars for ntv
 * \param pq pointer to the current PacketQueue
 * \param postpq
 */
static TmEcode DecodeDPDK(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        SCReturnInt(TM_ECODE_OK);

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief
 * \param tv
 * \param data Pointer to DecodeThreadVars.
 */
static TmEcode DecodeDPDKThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    if (data != NULL)
        DecodeThreadVarsFree(tv, data);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Registration Function for RecieveDPDK.
 */
void TmModuleReceiveDPDKRegister(void)
{
    tmm_modules[TMM_RECEIVEDPDK].name = "ReceiveDPDK";
    tmm_modules[TMM_RECEIVEDPDK].ThreadInit = ReceiveDPDKThreadInit;
    tmm_modules[TMM_RECEIVEDPDK].Func = NULL;
    tmm_modules[TMM_RECEIVEDPDK].PktAcqLoop = ReceiveDPDKLoop;
    tmm_modules[TMM_RECEIVEDPDK].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEDPDK].ThreadExitPrintStats = ReceiveDPDKThreadExitStats;
    tmm_modules[TMM_RECEIVEDPDK].ThreadDeinit = ReceiveDPDKThreadDeinit;
    tmm_modules[TMM_RECEIVEDPDK].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEDPDK].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEDPDK].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration Function for DecodeDPDK.
 */
void TmModuleDecodeDPDKRegister(void)
{
    tmm_modules[TMM_DECODEDPDK].name = "DecodeDPDK";
    tmm_modules[TMM_DECODEDPDK].ThreadInit = DecodeDPDKThreadInit;
    tmm_modules[TMM_DECODEDPDK].Func = DecodeDPDK;
    tmm_modules[TMM_DECODEDPDK].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEDPDK].ThreadDeinit = DecodeDPDKThreadDeinit;
    tmm_modules[TMM_DECODEDPDK].RegisterTests = NULL;
    tmm_modules[TMM_DECODEDPDK].cap_flags = 0;
    tmm_modules[TMM_DECODEDPDK].flags = TM_FLAG_DECODE_TM;
}

#endif /* HAVE_DPDK */
/* eof */
/**
* @}
*/
