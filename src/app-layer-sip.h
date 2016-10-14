/* Copyright (C) 2015 Open Information Security Foundation
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

#ifndef __APP_LAYER_SIP_H__
#define __APP_LAYER_SIP_H__

#include "detect-engine-state.h"

#include "queue.h"

void RegistersipParsers(void);
void sipParserRegisterTests(void);

typedef struct sipTransactionRequest_ {
    char *method;
    char *uri;
} sipTransactionRequest;

typedef struct sipTransactionResponse_ {
    TAILQ_ENTRY(sipTransactionResponse_) next;

    struct {
        int code;
        char *reason;
    } status;

} sipTransactionResponse;

typedef struct sipTransaction_ {

    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */

    sipTransactionRequest request;
    
    TAILQ_HEAD(, sipTransactionResponse_) response_list;

    /* flags indicating which loggers that have logged */
    uint32_t logged;

    uint32_t response_done : 1; /*<< Flag to be set when the response is
                                 * seen. */

    DetectEngineState *de_state;

    TAILQ_ENTRY(sipTransaction_) next;

} sipTransaction;

typedef struct sipState_ {

    TAILQ_HEAD(, sipTransaction_) tx_list; /**< List of sip transactions
                                       * associated with this
                                       * state. */

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */

    uint16_t events; /**< Number of application layer events created
                      * for this state. */

} sipState;

#endif /* __APP_LAYER_SIP_H__ */
