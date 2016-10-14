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
 *
 * SIP application layer detector and parser.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-byte.h"
#include "util-unittest.h"

#include "tm-threads.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-sip.h"

#ifdef HAVE_PJSIP

#include <pjsip.h>
#include <pjlib.h>

/**
 * Memory size to use in caching pool.
 * Default: 2MB
 */
#ifndef PJSIP_TEST_MEM_SIZE
#define PJSIP_TEST_MEM_SIZE       (2*1024*1024)
#endif

#define POOL_SIZE 8000

/* Defined in sip_parser.c */
void init_sip_parser(void);
void deinit_sip_parser(void);

/* Defined in sip_tel_uri.c */
pj_status_t pjsip_tel_uri_subsys_init(void);

static pjsip_endpoint *endpt;
static pj_caching_pool caching_pool;
//static pj_pool_t *pool;

/* The default port to probe for sip traffic if not provided in the
 * configuration file. */
#define SIP_DEFAULT_PORT "5060"

/* The minimum size for an SIP message. For some protocols this might
 * be the size of a header. */
#define SIP_MIN_FRAME_LEN 9

/* Enum of app-layer events for an sip protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For sip we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert sip any any -> any any (msg:"SURICATA sip empty message"; \
 *    app-layer-event:sip.empty_message; sid:X; rev:Y;)
 */
enum {
    SIP_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap sip_decoder_event_table[] = {
    {"EMPTY_MESSAGE", SIP_DECODER_EVENT_EMPTY_MESSAGE},
};

static sipTransaction *sipTxAlloc(sipState *sip)
{
    sipTransaction *tx = SCCalloc(1, sizeof(sipTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    TAILQ_INIT(&tx->response_list);
    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = sip->transaction_max++;

    TAILQ_INSERT_TAIL(&sip->tx_list, tx, next);

    return tx;
}

static void sipTxFree(void *tx)
{
    sipTransaction *siptx = tx;
    sipTransactionResponse *rsp = NULL, *trsp;

    AppLayerDecoderEventsFreeEvents(&siptx->decoder_events);

    if (siptx->request.method != NULL) {
        SCFree(siptx->request.method);
    }
    if (siptx->request.uri != NULL) {
        SCFree(siptx->request.uri);
    }

    TAILQ_FOREACH_SAFE(rsp, &siptx->response_list, next, trsp) {
        if (rsp->status.reason != NULL) {
            SCFree(rsp->status.reason);
        }
        TAILQ_REMOVE(&siptx->response_list, rsp, next);
        SCFree(rsp);
    }
    SCFree(tx);
}

static void *sipStateAlloc(void)
{
    SCLogDebug("Allocating sip state.");
    sipState *state = SCCalloc(1, sizeof(sipState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void sipStateFree(void *state)
{
    sipState *sip_state = state;
    sipTransaction *tx;
    SCLogDebug("Freeing sip state.");
    while ((tx = TAILQ_FIRST(&sip_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&sip_state->tx_list, tx, next);
        sipTxFree(tx);
    }
    SCFree(sip_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the sipState object.
 * \param tx_id the transaction ID to free.
 */
static void sipStateTxFree(void *state, uint64_t tx_id)
{
    sipState *sip = state;
    sipTransaction *tx = NULL, *ttx;

    SCLogDebug("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &sip->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&sip->tx_list, tx, next);
        sipTxFree(tx);
        return;
    }

    SCLogDebug("Transaction %"PRIu64" not found.", tx_id);
}

static int sipStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, sip_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "sip enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *sipGetEvents(void *state, uint64_t tx_id)
{
    sipState *sip_state = state;
    sipTransaction *tx;

    TAILQ_FOREACH(tx, &sip_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int sipHasEvents(void *state)
{
    sipState *sip = state;
    return sip->events;
}

/**
 * \brief Probe the input to see if it looks like sip.
 *
 * \retval ALPROTO_SIP if it looks like sip, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto sipProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    pj_pool_t *pool;
    pjsip_msg *parsed_msg;
    pjsip_parser_err_report err_list;
    pj_size_t msg_size = input_len;
    pj_thread_desc desc;
    pj_thread_t *this_thread;
    pj_status_t rc;
    ThreadVars *tv;

    if (input_len < SIP_MIN_FRAME_LEN) {
        SCLogDebug("Protocol not detected as ALPROTO_SIP.");
        return ALPROTO_UNKNOWN;
    }

    tv = TmThreadsGetCallingThread();
    if (unlikely(tv == NULL)) {
        return ALPROTO_UNKNOWN;
    }
    if (tv->sip_flags == 0) {
        pj_bzero(desc, sizeof(desc));
        rc = pj_thread_register(tv->name, desc, &this_thread);
        if (rc != PJ_SUCCESS) {
            return ALPROTO_UNKNOWN;
        }

        tv->sip_flags = 1;
    }
    pool = pjsip_endpt_create_pool(endpt, NULL, POOL_SIZE, POOL_SIZE);

    pj_list_init(&err_list);
    parsed_msg = pjsip_parse_msg(pool, (char *)input, msg_size, &err_list);
    if (parsed_msg == NULL) {
        pjsip_endpt_release_pool(endpt, pool);
        SCLogDebug("Protocol not detected as ALPROTO_SIP.");
        return ALPROTO_UNKNOWN;
    }

    pjsip_endpt_release_pool(endpt, pool);
    SCLogDebug("Detected as ALPROTO_SIP.");
    return ALPROTO_SIP;
}

static int sipParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    pj_pool_t *pool;
    pjsip_msg *parsed_msg;
    pjsip_parser_err_report err_list;
    pj_size_t msg_size;
    sipState *sip = state;

    SCLogDebug("Parsing sip request: len=%"PRIu32, input_len);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }
    msg_size = input_len;

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is sip, we'll just record the
     * request data. */

    /* Also, if this protocol may have a "protocol data unit" span
     * multiple chunks of data, which is always a possibility with
     * TCP, you may need to do some buffering here.
     *
     * For the sake of simplicity, buffering is left out here, but
     * even for an sip protocol we may want to buffer until a new
     * line is seen, assuming its text based.
     */

    pool = pjsip_endpt_create_pool(endpt, NULL, POOL_SIZE, POOL_SIZE);

    pj_list_init(&err_list);
    parsed_msg = pjsip_parse_msg(pool, (char *)input, msg_size, &err_list);
    if (parsed_msg == NULL) {
        goto end;
    }

    /* Allocate a transaction.
     *
     * But note that if a "protocol data unit" is not received in one
     * chunk of data, and the buffering is done on the transaction, we
     * may need to look for the transaction that this newly recieved
     * data belongs to.
     */
    sipTransaction *tx = sipTxAlloc(sip);
    if (unlikely(tx == NULL)) {
        SCLogDebug("Failed to allocate new sip tx.");
        goto end;
    }
    SCLogDebug("Allocated sip tx %"PRIu64".", tx->tx_id);
    //tx->request_msg = parsed_msg;
    //tx->request_msg = parsed_msg;
    tx->request.method = strdup(parsed_msg->line.req.method.name.ptr);
    tx->request.uri = NULL;

    if ((parsed_msg->type == PJSIP_REQUEST_MSG) &&
	    (parsed_msg->line.req.uri != NULL)) {
        pjsip_uri *sip_uri;
        uint8_t uribuf[1024];
        sip_uri = (pjsip_uri*) pjsip_uri_get_uri(parsed_msg->line.req.uri);
	    pj_ssize_t len = pjsip_uri_print( PJSIP_URI_IN_REQ_URI, sip_uri, (char *)uribuf, sizeof(uribuf)-1);
        if (len >= 0) {
            tx->request.uri = BytesToString(uribuf, len);
        }
    }
end:    
    pjsip_endpt_release_pool(endpt, pool);
    return 0;
}

static int sipParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    pj_pool_t *pool;
    pjsip_msg *parsed_msg;
    pjsip_parser_err_report err_list;
    pj_size_t msg_size = input_len;
    sipState *sip = state;
    sipTransaction *tx = NULL, *ttx;;

    SCLogDebug("Parsing sip response.");

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    /* Look up the existing transaction for this response. In the case
     * of sip, it will be the most recent transaction on the
     * sipState object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &sip->tx_list, next) {
        tx = ttx;
    }
    
    if (tx == NULL) {
        SCLogDebug("Failed to find transaction for response on sip state %p.",
            sip);
        return 0;
    }

    SCLogDebug("Found transaction %"PRIu64" for response on sip state %p.",
        tx->tx_id, sip);

    pool = pjsip_endpt_create_pool(endpt, NULL, POOL_SIZE, POOL_SIZE);

    pj_list_init(&err_list);
    parsed_msg = pjsip_parse_msg(pool, (char *)input, msg_size, &err_list);
    if (parsed_msg == NULL) {
        return 0;
    }

    sipTransactionResponse *rsp = SCMalloc(sizeof(sipTransactionResponse));
    if (unlikely(rsp == NULL)) {
        goto end;
    }
    //rsp->response_msg = parsed_msg;
    rsp->status.code = parsed_msg->line.status.code;
    pj_ssize_t len = parsed_msg->line.status.reason.slen;

    rsp->status.reason = BytesToString((const uint8_t *)parsed_msg->line.status.reason.ptr, len);
    TAILQ_INSERT_TAIL(&tx->response_list, rsp, next);

    /* Set the response_done flag for transaction state checking in
     * sipGetStateProgress(). */
    if ((parsed_msg->type != PJSIP_REQUEST_MSG) &&
        (parsed_msg->line.status.code != 100)) {
        tx->response_done = 1;
    }

end:
    pjsip_endpt_release_pool(endpt, pool);
    return 0;
}

static uint64_t sipGetTxCnt(void *state)
{
    sipState *sip = state;
    SCLogDebug("Current tx count is %"PRIu64".", sip->transaction_max);
    return sip->transaction_max;
}

static void *sipGetTx(void *state, uint64_t tx_id)
{
    sipState *sip = state;
    sipTransaction *tx;

    SCLogDebug("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &sip->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogDebug("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogDebug("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void sipSetTxLogged(void *state, void *vtx, uint32_t logger)
{
    sipTransaction *tx = (sipTransaction *)vtx;
    tx->logged |= logger;
}

static int sipGetTxLogged(void *state, void *vtx, uint32_t logger)
{
    sipTransaction *tx = (sipTransaction *)vtx;
    if (tx->logged & logger)
        return 1;

    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int sipGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the sip protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int sipGetStateProgress(void *tx, uint8_t direction)
{
    sipTransaction *siptx = tx;

    SCLogDebug("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", siptx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && siptx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For sip, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *sipGetTxDetectState(void *vtx)
{
    sipTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int sipSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    sipTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

#endif /* HAVE_PJSIP */

void RegistersipParsers(void)
{
#ifdef HAVE_PJSIP
    char *proto_name = "sip";

    /* Check if sip UDP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {

        SCLogDebug("sip UDP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_SIP, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogDebug("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, SIP_DEFAULT_PORT,
                ALPROTO_SIP, 0, SIP_MIN_FRAME_LEN, STREAM_TOSERVER,
                sipProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_SIP, 0, SIP_MIN_FRAME_LEN,
                    sipProbingParser)) {
                SCLogDebug("No SIP app-layer configuration, enabling SIP"
                    " detection UDP detection on port %s.",
                    SIP_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                    SIP_DEFAULT_PORT, ALPROTO_SIP, 0,
                    SIP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    sipProbingParser);
            }

        }
        pj_status_t rc;

        rc = pj_init();
        if (rc != PJ_SUCCESS) {
            SCLogDebug("sip protocol could not init pjlib.");
            return;
        }

        rc = pjlib_util_init();
        if (rc != PJ_SUCCESS) {
            SCLogDebug("sip protocol could not init pjlib util.");
            return;
        }
        pj_caching_pool_init( &caching_pool, &pj_pool_factory_default_policy,
              PJSIP_TEST_MEM_SIZE );

        rc = pjsip_endpt_create(&caching_pool.factory, "endpt", &endpt);
        if (rc != PJ_SUCCESS) {
            SCLogDebug("sip protocol could not create endpt.");
            pj_caching_pool_destroy(&caching_pool);
            return;
        }

        /* Init parser */
        init_sip_parser();
    }

    else {
        SCLogDebug("Protocol detecter and parser disabled for sip.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogDebug("Registering sip protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new sip flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_SIP,
            sipStateAlloc, sipStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_SIP,
            STREAM_TOSERVER, sipParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_SIP,
            STREAM_TOCLIENT, sipParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_SIP,
            sipStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_SIP,
            sipGetTxLogged, sipSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_SIP,
            sipGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_SIP,
            sipGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP,
            ALPROTO_SIP, sipGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_SIP,
            sipGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_SIP,
            sipHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_SIP,
            NULL, sipGetTxDetectState, sipSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_SIP,
            sipStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_SIP,
            sipGetEvents);

    }
    else {
        SCLogNotice("sip protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SIP,
        sipParserRegisterTests);
#endif

#endif /* HAVE_PJSIP */
}

#ifdef HAVE_PJSIP

#ifdef UNITTESTS
#endif

void sipParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}

#endif /* HAVE_PJSIP */
