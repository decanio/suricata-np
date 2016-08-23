/* Copyright (C) 2014 Open Information Security Foundation
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
* \file
*
* \author Tom DeCanio <decanio.tom@gmail.com>
*/

#ifndef __SOURCE_DPDK_H__
#define __SOURCE_DPDK_H__

#include "queue.h"

/* copy modes */
enum {
    DPDK_COPY_MODE_NONE,
    DPDK_COPY_MODE_TAP,
    DPDK_COPY_MODE_IPS,
};

#define DPDK_IFACE_NAME_LENGTH    48

typedef struct DPDKIfaceSettings_
{
    /* real inner interface name */
    char iface[DPDK_IFACE_NAME_LENGTH];

    int threads;
    /* sw ring flag for out_iface */
    int sw_ring;
    int promisc;
    int copy_mode;
    ChecksumValidationMode checksum_mode;
    char *bpf_filter;
} DPDKIfaceSettings;

typedef struct DPDKIfaceConfig_
{
    /* semantic interface name */
    char iface_name[DPDK_IFACE_NAME_LENGTH];

    /* settings for out capture device*/
    DPDKIfaceSettings in;

    /* semantic interface name */
    char *out_iface_name;

    /* settings for outgoing iface for IPS/TAP */
    DPDKIfaceSettings out;

    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} DPDKIfaceConfig;

typedef struct DPDKPacketVars_
{
    int ring_id;
    int slot_id;
    int dst_ring_id;
    /* DPDKThreadVars */
    void *ntv;
} DPDKPacketVars;

int DPDKGetRSSCount(const char *ifname);

void TmModuleReceiveDPDKRegister (void);
void TmModuleDecodeDPDKRegister (void);

#endif /* __SOURCE_DPDK_H__ */
