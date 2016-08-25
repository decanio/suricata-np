/* Copyright (C) 2016 Open Information Security Foundation
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
* \ingroup DPDK
*
* @{
*/

/**
* \file
*
* \author Tom DeCanio <decanio.tom@gmail.com>
*
* DPDK runmode
*
*/

#include "suricata-common.h"
#include "config.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-netmap.h"
#include "log-httplog.h"
#include "output.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-ioctl.h"

#include "source-dpdk-px.h"

extern int max_pending_packets;

static const char *default_mode_workers = NULL;

const char *RunModeDPDKGetDefaultMode(void)
{
    return default_mode_workers;
}

void RunModeIdsDPDKRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "single",
            "Single threaded netmap mode",
            RunModeIdsDPDKSingle);
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "workers",
            "Workers netmap mode, each thread does all"
                    " tasks from acquisition to logging",
            RunModeIdsDPDKWorkers);
    default_mode_workers = "workers";
    RunModeRegisterNewRunMode(RUNMODE_DPDK, "autofp",
            "Multi threaded netmap mode.  Packets from "
                    "each flow are assigned to a single detect "
                    "thread.",
            RunModeIdsDPDKAutoFp);
    return;
}

#ifdef HAVE_DPDK

static void DPDKDerefConfig(void *conf)
{
    DPDKIfaceConfig *pfp = (DPDKIfaceConfig *)conf;
    /* config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 0) {
        SCFree(pfp);
    }
}

static int ParseDPDKSettings(DPDKIfaceSettings *ns, const char *iface,
        ConfNode *if_root, ConfNode *if_default)
{
    ns->threads = 0;
    ns->promisc = 1;
    ns->checksum_mode = CHECKSUM_VALIDATION_AUTO;
    ns->copy_mode = DPDK_COPY_MODE_NONE;

    strlcpy(ns->iface, iface, sizeof(ns->iface));
    if (ns->iface[0]) {
        size_t len = strlen(ns->iface);
        if (ns->iface[len-1] == '+') {
            ns->iface[len-1] = '\0';
            ns->sw_ring = 1;
        }
    }

    char *bpf_filter = NULL;
    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            ns->bpf_filter = bpf_filter;
            SCLogInfo("Going to use command-line provided bpf filter '%s'",
                    ns->bpf_filter);
        }
    }

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("Unable to find DPDK config for "
                "interface \"%s\" or \"default\", using default values",
                iface);
        goto finalize;

    /* If there is no setting for current interface use default one as main iface */
    } else if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    char *threadsstr = NULL;
    if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        ns->threads = 0;
    } else {
        if (strcmp(threadsstr, "auto") == 0) {
            ns->threads = 0;
        } else {
            ns->threads = (uint8_t)atoi(threadsstr);
        }
    }

    /* load netmap bpf filter */
    /* command line value has precedence */
    if (ns->bpf_filter == NULL) {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_filter) == 1) {
            if (strlen(bpf_filter) > 0) {
                ns->bpf_filter = bpf_filter;
                SCLogInfo("Going to use bpf filter %s", ns->bpf_filter);
            }
        }
    }

    int boolval = 0;
    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogInfo("Disabling promiscuous mode on iface %s", ns->iface);
        ns->promisc = 0;
    }

    char *tmpctype;
    if (ConfGetChildValueWithDefault(if_root, if_default,
                "checksum-checks", &tmpctype) == 1)
    {
        if (strcmp(tmpctype, "auto") == 0) {
            ns->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            ns->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            ns->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid value for "
                    "checksum-checks for %s", iface);
        }
    }

    char *copymodestr;
    if (ConfGetChildValueWithDefault(if_root, if_default,
                "copy-mode", &copymodestr) == 1)
    {
        if (strcmp(copymodestr, "ips") == 0) {
            ns->copy_mode = DPDK_COPY_MODE_IPS;
        } else if (strcmp(copymodestr, "tap") == 0) {
            ns->copy_mode = DPDK_COPY_MODE_TAP;
        } else {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid copy-mode "
                    "(valid are tap, ips)");
        }
    }

    char *rxringstr;
    if (ConfGetChildValueWithDefault(if_root, if_default,
                "rx-ring", &rxringstr) == 1) {
        strncpy(ns->rx_ring, rxringstr, sizeof(ns->rx_ring)-1);
    } else {
        /* Use DPDK default */
        strcpy(ns->rx_ring, "MProc_Client_%u_RX");
    }

    char *rtnringstr;
    if (ConfGetChildValueWithDefault(if_root, if_default,
                "rx-ring", &rtnringstr) == 1) {
        strncpy(ns->rtn_ring, rtnringstr, sizeof(ns->rtn_ring)-1);
    } else {
        /* Use DPDK default */
        strcpy(ns->rx_ring, "MProc_Client_%u_RTN");
    }

finalize:

    if (ns->sw_ring) {
        /* just one thread per interface supported */
        ns->threads = 1;
    } else if (ns->threads == 0) {
#if 0
        /* As DPDKGetRSSCount is broken on Linux, first run
         * GetIfaceRSSQueuesNum. If that fails, run DPDKGetRSSCount */
        ns->threads = GetIfaceRSSQueuesNum(ns->iface);
        if (ns->threads == 0) {
            ns->threads = DPDKGetRSSCount(ns->iface);
        }
#else
	/* figure out how many rings we are trying to read */
        ns->threads = 1;
#endif
    }
    if (ns->threads <= 0) {
        ns->threads = 1;
    }

    return 0;
}

/**
* \brief extract information from config file
*
* The returned structure will be freed by the thread init function.
* This is thus necessary to or copy the structure before giving it
* to thread or to reparse the file for each thread (and thus have
* new structure.
*
* \return a DPDKIfaceConfig corresponding to the interface name
*/
static void *ParseDPDKConfig(const char *iface_name)
{
    ConfNode *if_root = NULL;
    ConfNode *if_default = NULL;
    ConfNode *netmap_node;
    char *out_iface = NULL;

    if (iface_name == NULL) {
        return NULL;
    }

    DPDKIfaceConfig *aconf = SCMalloc(sizeof(*aconf));
    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    memset(aconf, 0, sizeof(*aconf));
    aconf->DerefFunc = DPDKDerefConfig;
    strlcpy(aconf->iface_name, iface_name, sizeof(aconf->iface_name));
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);

    /* Find initial node */
    netmap_node = ConfGetNode("netmap");
    if (netmap_node == NULL) {
        SCLogInfo("Unable to find netmap config using default value");
    } else {
        if_root = ConfFindDeviceConfig(netmap_node, aconf->iface_name);
        if_default = ConfFindDeviceConfig(netmap_node, "default");
    }

    /* parse settings for capture iface */
    ParseDPDKSettings(&aconf->in, aconf->iface_name, if_root, if_default);

    /* if we have a copy iface, parse that as well */
    if (netmap_node != NULL) {
        if (ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1) {
            if (strlen(out_iface) > 0) {
                if_root = ConfFindDeviceConfig(netmap_node, out_iface);
                ParseDPDKSettings(&aconf->out, out_iface, if_root, if_default);
            }
        }
    }

    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->in.threads);
    SCLogPerf("Using %d threads for interface %s", aconf->in.threads,
            aconf->iface_name);

    return aconf;
}

static int DPDKConfigGeThreadsCount(void *conf)
{
    DPDKIfaceConfig *aconf = (DPDKIfaceConfig *)conf;
    return aconf->in.threads;
}

int DPDKRunModeIsIPS()
{
    int nlive = LiveGetDeviceCount();
    int ldev;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *netmap_node;
    int has_ips = 0;
    int has_ids = 0;

    /* Find initial node */
    netmap_node = ConfGetNode("netmap");
    if (netmap_node == NULL) {
        return 0;
    }

    if_default = ConfNodeLookupKeyValue(netmap_node, "interface", "default");

    for (ldev = 0; ldev < nlive; ldev++) {
        const char *live_dev = LiveGetDeviceName(ldev);
        if (live_dev == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
            return 0;
        }
        char *copymodestr = NULL;
        if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);

        if (if_root == NULL) {
            if (if_default == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                return 0;
            }
            if_root = if_default;
        }

        if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
            if (strcmp(copymodestr, "ips") == 0) {
                has_ips = 1;
            } else {
                has_ids = 1;
            }
        } else {
            has_ids = 1;
        }
    }

    if (has_ids && has_ips) {
        SCLogInfo("DPDK mode using IPS and IDS mode");
        for (ldev = 0; ldev < nlive; ldev++) {
            const char *live_dev = LiveGetDeviceName(ldev);
            if (live_dev == NULL) {
                SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                return 0;
            }
            if_root = ConfNodeLookupKeyValue(netmap_node, "interface", live_dev);
            char *copymodestr = NULL;

            if (if_root == NULL) {
                if (if_default == NULL) {
                    SCLogError(SC_ERR_INVALID_VALUE, "Problem with config file");
                    return 0;
                }
                if_root = if_default;
            }

            if (! ((ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) &&
                    (strcmp(copymodestr, "ips") == 0))) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "DPDK IPS mode used and interface '%s' is in IDS or TAP mode. "
                                "Sniffing '%s' but expect bad result as stream-inline is activated.",
                        live_dev, live_dev);
            }
        }
    }

    return has_ips;
}

#endif // #ifdef HAVE_DPDK

int RunModeIdsDPDKAutoFp(void)
{
    SCEnter();

#ifdef HAVE_DPDK
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();

    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    SCLogDebug("live_dev %s", live_dev);

    ret = RunModeSetLiveCaptureAutoFp(
                              ParseDPDKConfig,
                              DPDKConfigGeThreadsCount,
                              "ReceiveDPDK",
                              "DecodeDPDK", thread_name_autofp,
                              live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsDPDKAutoFp initialised");
#endif /* HAVE_DPDK */

    SCReturnInt(0);
}

/**
* \brief Single thread version of the netmap processing.
*/
int RunModeIdsDPDKSingle(void)
{
    SCEnter();

#ifdef HAVE_DPDK
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureSingle(
                                    ParseDPDKConfig,
                                    DPDKConfigGeThreadsCount,
                                    "ReceiveDPDK",
                                    "DecodeDPDK", thread_name_single,
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsDPDKSingle initialised");

#endif /* HAVE_DPDK */
    SCReturnInt(0);
}

/**
* \brief Workers version of the netmap processing.
*
* Start N threads with each thread doing all the work.
*
*/
int RunModeIdsDPDKWorkers(void)
{
    SCEnter();

#ifdef HAVE_DPDK
    int ret;
    char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("netmap.live-interface", &live_dev);

    ret = RunModeSetLiveCaptureWorkers(
                                    ParseDPDKConfig,
                                    DPDKConfigGeThreadsCount,
                                    "ReceiveDPDK",
                                    "DecodeDPDK", thread_name_workers,
                                    live_dev);
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Unable to start runmode");
        exit(EXIT_FAILURE);
    }

    SCLogDebug("RunModeIdsDPDKWorkers initialised");

#endif /* HAVE_DPDK */
    SCReturnInt(0);
}

/**
* @}
*/
