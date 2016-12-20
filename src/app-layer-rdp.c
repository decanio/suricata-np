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

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-rdp.h"

#include "decode-events.h"
#include "conf.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-util.h"
#include "flow-private.h"

#include "util-byte.h"

//#define PRINT

#define TPKT_LEN 4

static RDPTransaction *RDPTransactionCreate(void)
{
    return SCCalloc(1, sizeof(RDPTransaction));
}

static void RDPTransactionFree(RDPTransaction *tx, void *alstate)
{
    if (tx->de_state != NULL)
        DetectEngineStateFree(tx->de_state);
    SCFree(tx);
}

static void RDPStateTransactionFree (void *alstate, uint64_t tx_id)
{
#ifdef PRINT
    printf("RDPStateTransactionFree tx_id %ld\n", tx_id);
#endif
    RDPState *rdp_state = alstate;
    RDPTransaction *tx = NULL;
    TAILQ_FOREACH(tx, &rdp_state->tx_list, next) {
        if (tx_id < tx->tx_id)
            break;
        else if (tx_id > tx->tx_id)
            continue;

        if (tx == rdp_state->curr_tx)
            rdp_state->curr_tx = NULL;
        TAILQ_REMOVE(&rdp_state->tx_list, tx, next);
#ifdef PRINT
        printf("Freeing TX\n");
#endif
        RDPTransactionFree(tx, alstate);
        break;
    }
}

/** \retval cnt highest tx id */
static uint64_t RDPStateGetTxCnt(void *state)
{
    uint64_t cnt = 0;
#ifdef PRINT
    printf("RDPStateGetTxCnt: ");
#endif
    RDPState *rdp_state = state;
    if (rdp_state) {
        cnt = rdp_state->tx_cnt;
    }
    SCLogDebug("returning %"PRIu64, cnt);
    return cnt;
}

static void *RDPStateGetTx(void *alstate, uint64_t id)
{
    RDPState *rdp_state = alstate;
#ifdef PRINT
    printf("RDPStateGetTx td_id: %ld\n", id);
#endif
    if (rdp_state) {
        RDPTransaction *tx = NULL;

        if (rdp_state->curr_tx == NULL)
            return NULL;
        if (rdp_state->curr_tx->tx_id == id)
            return rdp_state->curr_tx;

        TAILQ_FOREACH(tx, &rdp_state->tx_list, next) {
            if (tx->tx_id == id)
                return tx;
        }
    }
    return NULL;
}

static int RDPStateGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

static int RDPStateGetAlstateProgress(void *vtx, uint8_t direction)
{
    RDPTransaction *tx = vtx;
#ifdef PRINT
    printf("RDPStateGetAlstateProgress: tx_id: %ld done: %d\n", tx->tx_id, tx->done);
#endif
    return tx->done;
}

static inline int RDPIsTPKT(uint8_t *input, uint32_t ilen)
{
    unsigned length;

    /* can probably beef up this check a bit more */
    if (ilen >= TPKT_LEN) {
        if ((input[0] == 0x03) && (input[1] == 0x00)) {
            length = input[2]<<8;
            length |= input[3];
            if ((length >= 7) && (length <= 65535) && (length <= ilen))
                 return (int)length;
        }
    }
    return -1;
}

static int RDPDecodeX224Data(Flow *f, uint8_t direction, void *alstate, AppLayerParserState *pstate,
                     uint8_t *input, uint32_t ilen)
{
    SCEnter();
    RDPState *rdp_state = (RDPState *) alstate;
    RDPTransaction *tx;
    uint8_t *p = input;
    uint8_t type;
    
    type = *p;
    
    switch (type) {
        case T125_TYPE_ERECT_DOM_REQ:
            SCLogDebug("T125_TYPE_ERECT_DOM_REQ");
            break;
        case T125_TYPE_MSCCONNECT:
            if (*(p + 1) & 1) {
                SCLogDebug("T125_TYPE_MSCONNECT request");
                if (ilen > 64 + 6) {
                    uint8_t *p1 = memmem(p, ilen - 6, "Duca", 4);
                    if (likely(p1 != NULL)) {
                        tx = RDPTransactionCreate();
                        if (likely(tx != NULL)) {
                            tx->type = RDP_TYPE_T125_MSCCONNECT;
                            tx->tx_id = rdp_state->tx_cnt++;
                            rdp_state->curr_tx = tx;
                            uint8_t *rdp = p1 + 6;
                            uint16_t hdrType;
                            hdrType = rdp[1] << 8 | rdp[0];
                            switch (hdrType) {
                                case RDP_CLIENT_CORE_DATA:
                                    tx->t125_connect.versionMajor = rdp[4]|rdp[5]<<8;
                                    tx->t125_connect.versionMinor = rdp[6]|rdp[7]<<8;
                                    tx->t125_connect.desktopWidth = rdp[8]|rdp[9]<<8;
                                    tx->t125_connect.desktopHeight = rdp[10]|rdp[11]<<8;
                                    tx->t125_connect.colorDepth = rdp[12]|rdp[13]<<8;
                                    tx->t125_connect.SASSequence = rdp[14]|rdp[15]<<8;
                                    tx->t125_connect.keyboardLayout = rdp[16]|rdp[17]<<8|rdp[18]<<16|rdp[19]<<24;
                                    tx->t125_connect.clientBuild = rdp[20]|rdp[21]<<8|rdp[22]<<16|rdp[23]<<24;
                                    memcpy(tx->t125_connect.clientName, &rdp[24], 32);
                                    memcpy(tx->t125_connect.clientDigProductId, &rdp[146], 64);
                                    tx->t125_connect.keyboardType = rdp[56]|rdp[57]<<8|rdp[58]<<16|rdp[59]<<24;
                                    tx->t125_connect.keyboardSubtype = rdp[60]|rdp[61]<<8|rdp[62]<<16|rdp[63]<<24;
                                    break;
                            }
                            TAILQ_INSERT_TAIL(&rdp_state->tx_list, tx, next);
                        }
                    }
                }
            } else {
                SCLogDebug("T125_TYPE_MSCONNECT reply");
                tx = rdp_state->curr_tx;
                /* TBD: need to dig deeper for encryption data */
                rdp_state->flags |= RDP_FLAGS_ENCRYPTED;
                if (tx != NULL) {
                    tx->done = 1;
                }
            }
            break;
        case T125_TYPE_ATTACH_USER_REQ:
            SCLogDebug("T125_TYPE_ATTACH_USER_REQ");
            tx = RDPTransactionCreate();
            if (unlikely(tx != NULL)) {
                tx->type = RDP_TYPE_T125_USER;
                rdp_state->curr_tx = tx;

                tx->tx_id = rdp_state->tx_cnt++;
#ifdef PRINT
                printf("tx_id: %ld\n", tx->tx_id);
#endif
                TAILQ_INSERT_TAIL(&rdp_state->tx_list, tx, next);
            }
            break;
        case T125_TYPE_ATTACH_USER_CONF:
            SCLogDebug("T125_TYPE_ATTACH_USER_CONF");
            tx = rdp_state->curr_tx;
            if (tx != NULL) {
                tx->done = 1;
            }
            break;
        case T125_TYPE_JOIN_REQ:
            SCLogDebug("T125_TYPE_JOIN_REQ");
            tx = RDPTransactionCreate();
            if (unlikely(tx != NULL)) {
                tx->type = RDP_TYPE_T125_JOIN;
                rdp_state->curr_tx = tx;

                tx->tx_id = rdp_state->tx_cnt++;

#ifdef PRINT
                printf("tx_id: %ld\n", tx->tx_id);
#endif

                tx->t125_join.channelId = p[3]<<8|p[4];

                TAILQ_INSERT_TAIL(&rdp_state->tx_list, tx, next);
            }
            break;
        case T125_TYPE_JOIN_CONF:
            SCLogDebug("T125_TYPE_JOIN_CONF");
            tx = rdp_state->curr_tx;
            if (tx != NULL) {
#ifdef PRINT
                printf("tx_id: %ld done\n", tx->tx_id);
#endif
                tx->done = 1;
            }
            break;
        default:
            SCLogDebug("UNKNOWN");
            rdp_state->flags |= RDP_FLAGS_ENCRYPTED;
            break;
    }
    SCReturnInt(0);
}

static int RDPDecodeX224(Flow *f, uint8_t direction, void *alstate, AppLayerParserState *pstate,
                     uint8_t *input, uint32_t ilen)
{
    SCEnter();
    RDPState *rdp_state = (RDPState *) alstate;
    RDPTransaction *tx;
    uint8_t *p = input;
    uint8_t LengthIndicator;
    uint8_t TypeCredit;

    if ((rdp_state->flags & RDP_FLAGS_ENCRYPTED) != 0) {
        SCReturnInt(0);
    }
        
    LengthIndicator = *p;
    
    if ((uint32_t)LengthIndicator <= ilen - 1) {
        TypeCredit = *(p + 1);
        switch (TypeCredit) {
            case X224_TYPE_CONN_REQUEST:
                tx = RDPTransactionCreate();
                if (tx != NULL) {
                    tx->type = RDP_TYPE_X224_CONNECT;
                    tx->x224_connect.token_len = 0;
                    tx->x224_connect.token = NULL;
                    if (ilen > 9) {
                        if ((*(p + ilen - 2) == '\r') &&
                            (*(p + ilen - 1) == '\n')) {
                            tx->x224_connect.token_len = ilen - 7 -2;
                            if (tx->x224_connect.token_len != 0) {
                                tx->x224_connect.token = SCMalloc(tx->x224_connect.token_len + 1);
                                if (tx->x224_connect.token != NULL) {
                                    memcpy(tx->x224_connect.token, p + 7,
                                           tx->x224_connect.token_len);
                                    tx->x224_connect.token[tx->x224_connect.token_len] = '\0';
                                } else {
                                    tx->x224_connect.token_len = 0;
                                }
                            }
                        }
                    }
                    rdp_state->curr_tx = tx;

                    tx->tx_id = rdp_state->tx_cnt++;
                    TAILQ_INSERT_TAIL(&rdp_state->tx_list, tx, next);
                }
                break;
            case X224_TYPE_CONN_CONFIRM:
                tx = rdp_state->curr_tx;
                if (tx != NULL) {
                    tx->done = 1;
                }
                break;
            case X224_TYPE_DATA: {
                int parsed = LengthIndicator + 1;
                RDPDecodeX224Data(f, direction, alstate, pstate, input + parsed, ilen - parsed);
                }
                break;
            default:
                //rdp_state->flags |= RDP_FLAGS_ENCRYPTED;
                break;
        }
    }
	
    SCReturnInt(0);
}

/**
 * \internal
 * \brief RDP parser.
 *
 *        On parsing error, this should be the only function that should reset
 *        the parser state, to avoid multiple functions in the chain reseting
 *        the parser state.
 *
 * \param direction 0 for toserver, 1 for toclient.
 * \param alstate   Pointer to the state.
 * \param pstate    Application layer parser state for this session.
 * \param input     Pointer the received input data.
 * \param input_len Length in bytes of the received data.
 * \param output    Pointer to the list of parsed output elements.
 *
 * \retval >=0 On success.
 */
static int RDPDecodeTPKT(Flow *f, uint8_t direction, void *alstate, AppLayerParserState *pstate,
                     uint8_t *input, uint32_t ilen)
{
    SCEnter();
    RDPState *rdp_state = (RDPState *)alstate;
    int length;
    uint32_t parsed;

    rdp_state->f = f;

#ifdef PRINT
    printf("RDP segment ======= (%u)\n", ilen);
    PrintRawDataFp(stdout, input, ilen);
    printf("===================\n");
#endif

    if ((length = RDPIsTPKT(input, ilen)) < 0)
        SCReturnInt(ilen);
    
    parsed = TPKT_LEN;
    
    RDPDecodeX224(f, direction, alstate, pstate, input + parsed, length - parsed);

    SCReturnInt(length);
}

int RDPParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
                         uint8_t *input, uint32_t input_len,
                         void *local_data)
{
    uint32_t parsed = 0;
	
    while (parsed < input_len) {
        parsed += RDPDecodeTPKT(f, 0 /* toserver */, alstate, pstate, input + parsed, input_len - parsed);
    }
    return 0;
}

int RDPParseServerRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
                         uint8_t *input, uint32_t input_len,
                         void *local_data)
{
    uint32_t parsed = 0;
	
    while (parsed < input_len) {
        parsed += RDPDecodeTPKT(f, 1 /* toclient */, alstate, pstate, input + parsed, input_len + parsed);
    }
    return 0;
}

/**
 * \internal
 * \brief Function to allocate the RDP state memory.
 */
void *RDPStateAlloc(void)
{
    RDPState *rdp_state = SCMalloc(sizeof(RDPState));
    if (unlikely(rdp_state == NULL))
        return NULL;
    memset(rdp_state, 0, sizeof(RDPState));
    
    TAILQ_INIT(&rdp_state->tx_list);
    
    return (void *)rdp_state;
}

/**
 * \internal
 * \brief Function to free the RDP state memory.
 */
void RDPStateFree(void *p)
{
    RDPState *rdp_state = (RDPState *)p;

    SCFree(rdp_state);

    return;
}

static uint16_t RDPProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset)
{
    /* probably a rst/fin sending an eof */
    if (ilen == 0)
        return ALPROTO_UNKNOWN;

    if (RDPIsTPKT(input, ilen) >= 0) {
        return ALPROTO_RDP;
    }

    return ALPROTO_FAILED;
}

static DetectEngineState *RDPGetTxDetectState(void *vtx)
{
    RDPTransaction *tx = (RDPTransaction *)vtx;
    return tx->de_state;
}

static int RDPSetTxDetectState(void *state, void *vtx, DetectEngineState *s)
{
    RDPTransaction *tx = (RDPTransaction *)vtx;
    tx->de_state = s;
    return 0;
}

static int RDPRegisterPatternsForProtocolDetection(void)
{
    return 0;
}

/**
 * \brief Function to register the RDP protocol parser and other functions
 */
void RegisterRDPParsers(void)
{
    char *proto_name = "rdp";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_RDP, proto_name);

        if (RDPRegisterPatternsForProtocolDetection() < 0)
            return;

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                          "3389",
                                          ALPROTO_RDP,
                                          0, 3,
                                          STREAM_TOSERVER,
                                          RDPProbingParser, NULL);
        } else {
            AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                proto_name, ALPROTO_RDP,
                                                0, 3,
                                                RDPProbingParser, NULL);
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_RDP, STREAM_TOSERVER,
                                     RDPParseClientRecord);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_RDP, STREAM_TOCLIENT,
                                     RDPParseServerRecord);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_RDP, NULL,
                                               RDPGetTxDetectState, RDPSetTxDetectState);

        //AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_RDP, RDPStateGetEventInfo);

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_RDP, RDPStateAlloc, RDPStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_RDP, STREAM_TOSERVER | STREAM_TOCLIENT);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_RDP, RDPStateTransactionFree);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_RDP, RDPStateGetAlstateProgress);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_RDP, RDPStateGetTxCnt);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_RDP, RDPStateGetTx);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_RDP,
                                                               RDPStateGetAlstateProgressCompletionStatus);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_RDP, RDPParserRegisterTests);
#endif

    return;
}

/***************************************Unittests******************************/

#ifdef UNITTESTS

#endif /* UNITTESTS */

void RDPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif /* UNITTESTS */

    return;
}
