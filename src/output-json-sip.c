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
 * Implement JSON/eve logging app-layer SIP.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-sip.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogsipFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogsipFileCtx;

typedef struct LogsipLogThread_ {
    LogsipFileCtx *siplog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogsipLogThread;

static void JsonSIPRequest(json_t *js, sipTransactionRequest *req)
{
    if (req->method != NULL) {
        json_object_set_new(js, "method", json_string(req->method));
    }
        
    if (req->uri != NULL) {
        json_object_set_new(js, "uri", json_string(req->uri));
    }
}

static void JsonSIPResponse(json_t *js, sipTransactionResponse *rsp)
{
	/* Add status code. */
    json_object_set_new(js, "status_code", json_integer(rsp->status.code));

    /* Add reason text. */
    if (rsp->status.reason != NULL) {
        json_object_set_new(js, "reason", json_string(rsp->status.reason));
    }
}

static int JsonSIPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    sipTransaction *siptx = tx;
    LogsipLogThread *thread = thread_data;
    json_t *js, *sipjs, *reqjs, *rspjs, *rspjsa;

    SCLogDebug("Logging sip transaction %"PRIu64".", siptx->tx_id);
    
    js = CreateJSONHeader((Packet *)p, 0, "sip");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    sipjs = json_object();
    if (unlikely(sipjs == NULL)) {
        goto error;
    }

    reqjs = json_object();
    if (unlikely(reqjs == NULL)) {
        json_decref(sipjs);
        goto error;
    }
    JsonSIPRequest(reqjs, &siptx->request);

    json_object_set_new(sipjs, "request", reqjs);
    rspjsa = json_array();
    if (unlikely(rspjsa == NULL)) {
        json_decref(reqjs);
        json_decref(sipjs);
        goto error;
    }

    sipTransactionResponse *rsp;
    TAILQ_FOREACH(rsp, &siptx->response_list, next) {
        rspjs = json_object();
        if (unlikely(rspjs == NULL)) {
            json_decref(rspjsa);
            json_decref(reqjs);
            json_decref(sipjs);
            goto error;
        }
        JsonSIPResponse(rspjs, rsp);
        json_array_append_new(rspjsa, rspjs);
    }
    json_object_set_new(sipjs, "response", rspjsa);
    
    json_object_set_new(js, "sip", sipjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->siplog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;
    
error:
    if (sipjs != NULL) {
        json_decref(sipjs);
    }
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputsipLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogsipFileCtx *siplog_ctx = (LogsipFileCtx *)output_ctx->data;
    SCFree(siplog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputsipLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogsipFileCtx *siplog_ctx = SCCalloc(1, sizeof(*siplog_ctx));
    if (unlikely(siplog_ctx == NULL)) {
        return NULL;
    }
    siplog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(siplog_ctx);
        return NULL;
    }
    output_ctx->data = siplog_ctx;
    output_ctx->DeInit = OutputsipLogDeInitCtxSub;

    SCLogDebug("sip log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SIP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonsipLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogsipLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogsip.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->siplog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonsipLogThreadDeinit(ThreadVars *t, void *data)
{
    LogsipLogThread *thread = (LogsipLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonsipLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_SIP, "eve-log", "JsonsipLog",
        "eve-log.sip", OutputsipLogInitSub, ALPROTO_SIP,
        JsonSIPLogger, JsonsipLogThreadInit,
        JsonsipLogThreadDeinit, NULL);

    SCLogDebug("sip JSON logger registered.");
}

#else /* No JSON support. */

void JsonsipLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
