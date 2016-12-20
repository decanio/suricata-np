/* Copyright (C) 2007-2015 Open Information Security Foundation
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
 *
 */

#ifndef __APP_LAYER_RDP_H__
#define __APP_LAYER_RDP_H__

#include "decode-events.h"
#include "queue.h"

enum {
	RDP_TYPE_X224_CONNECT,
	RDP_TYPE_T125_MSCCONNECT,
	RDP_TYPE_T125_USER,
	RDP_TYPE_T125_JOIN
};

typedef struct RDPTransaction_ {
    uint64_t tx_id;  /**< transaction id */
    uint16_t tx_num; /**< internal: id */
    uint8_t done;
    uint8_t type;
    union {
        struct {
            uint8_t *token;
            size_t token_len;
        } x224_connect;
        struct {
        } t125_user;
        struct {
            uint16_t channelId;
        } t125_join;
        struct {
            uint16_t versionMajor;
            uint16_t versionMinor;
            uint16_t desktopWidth;
            uint16_t desktopHeight;
            uint16_t colorDepth;
            uint16_t SASSequence;
            uint32_t clientBuild;
            uint8_t  clientName[32];
            uint8_t  clientDigProductId[64];
            uint16_t keyboardLayout;
            uint32_t keyboardType;
            uint32_t keyboardSubtype;

        } t125_connect;
    };
    DetectEngineState *de_state;
    TAILQ_ENTRY(RDPTransaction_) next;	
} RDPTransaction;

/**
 * \brief RDP state structure.
 *
 *        Structure to store the RDP state values.
 */
typedef struct RDPState_ {
    Flow *f;

    /* holds some state flags we need */
    uint32_t flags;
    
    RDPTransaction *curr_tx;
    TAILQ_HEAD(, RDPTransaction_) tx_list; /**< transaction list */
    uint64_t tx_cnt;
} RDPState;

#define RDP_FLAGS_ENCRYPTED        0x00000001

#define X224_TYPE_CONN_CONFIRM     0xD0
#define X224_TYPE_CONN_REQUEST     0xE0
#define X224_TYPE_DATA             0xF0

#define T125_TYPE_ERECT_DOM_REQ    0x04
#define T125_TYPE_MSCCONNECT       0x7F
#define T125_TYPE_ATTACH_USER_REQ  0x28
#define T125_TYPE_ATTACH_USER_CONF 0x2E
#define T125_TYPE_JOIN_REQ         0x38
#define T125_TYPE_JOIN_CONF        0x3E

#define RDP_CLIENT_CORE_DATA       0xc001

void RegisterRDPParsers(void);
void RDPParserRegisterTests(void);

#endif /* __APP_LAYER_RDP_H__ */
