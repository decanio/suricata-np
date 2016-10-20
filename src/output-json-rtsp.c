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
 * Implement JSON/eve logging app-layer RTSP.
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

#include "app-layer-rtsp.h"

#if defined(HAVE_LIBJANSSON) && defined(HAVE_GSTREAMER)

typedef struct LogrtspFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogrtspFileCtx;

typedef struct LogrtspLogThread_ {
    LogrtspFileCtx *rtsplog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogrtspLogThread;

static char *RequestMethodStr(GstRTSPMethod method)
{
    switch (method) {
        case GST_RTSP_DESCRIBE:
            return "DESCRIBE";
        case GST_RTSP_ANNOUNCE:
            return "ANNOUNCE";
        case GST_RTSP_GET_PARAMETER:
            return "GET PARAMETER";
        case GST_RTSP_OPTIONS:
            return "OPTIONS";
        case GST_RTSP_PAUSE:
            return "PAUSE";
        case GST_RTSP_PLAY:
            return "PLAY";
        case GST_RTSP_RECORD:
            return "RECORD";
        case GST_RTSP_REDIRECT:
            return "REDIRECT";
        case GST_RTSP_SETUP:
            return "SETUP";
        case GST_RTSP_SET_PARAMETER:
            return "SET PARAMETER";
        case GST_RTSP_TEARDOWN:
            return "TEARDOWN";
        case GST_RTSP_GET:
            return "GET";
        case GST_RTSP_POST:
            return "POST";
        case GST_RTSP_INVALID:
        default:
            return "";
    }
}

static int JsonrtspLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    rtspTransaction *rtsptx = tx;
    LogrtspLogThread *thread = thread_data;
    json_t *js, *rtspjs = NULL, *reqjs = NULL, *rspjs = NULL;
    char *s;

    SCLogDebug("Logging rtsp transaction %"PRIu64".", rtsptx->tx_id);
    
    js = CreateJSONHeader((Packet *)p, 0, "rtsp");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    rtspjs = json_object();
    if (unlikely(rtspjs == NULL)) {
        goto error;
    }

    reqjs = json_object();
    if (unlikely(reqjs == NULL)) {
        goto error;
    }

    rspjs = json_object();
    if (unlikely(rspjs == NULL)) {
        goto error;
    }

    /* fill the request */
    s = RequestMethodStr(rtsptx->request.type_data.request.method);
    json_object_set_new(reqjs, "type", json_string(s));
    json_object_set_new(reqjs, "uri", json_string(rtsptx->request.type_data.request.uri));
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_CSEQ,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "cseq", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_USER_AGENT,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "user_agent", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_ACCEPT,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "accept", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_ACCEPT_CHARSET,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "accept_charset", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_X_ACCEPT_AUTHENT,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "x_accept_authentication", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_ACCEPT_LANGUAGE,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "accept_language", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_SESSION,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "session", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_TRANSPORT,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "transport", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_CONTENT_TYPE,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "content_type", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_CONTENT_LENGTH,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "content_length", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->request,
                                    GST_RTSP_HDR_SUPPORTED,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "supported", json_string(s));
    }

    json_object_set_new(rtspjs, "request", reqjs);

    /* fill the response */
    json_object_set_new(rspjs, "code", json_integer(rtsptx->response.type_data.response.code));
    json_object_set_new(rspjs, "reason", json_string(rtsptx->response.type_data.response.reason));
    if (gst_rtsp_message_get_header(&rtsptx->response,
                                    GST_RTSP_HDR_TRANSPORT,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(rspjs, "transport", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->response,
                                    GST_RTSP_HDR_CONTENT_TYPE,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(rspjs, "content_type", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->response,
                                    GST_RTSP_HDR_CONTENT_LENGTH,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(rspjs, "content_length", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->response,
                                    GST_RTSP_HDR_SERVER,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(reqjs, "server", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->response,
                                    GST_RTSP_HDR_SUPPORTED,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(rspjs, "supported", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->response,
                                    GST_RTSP_HDR_RTP_INFO,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(rspjs, "rtp_info", json_string(s));
    }
    if (gst_rtsp_message_get_header(&rtsptx->response,
                                    GST_RTSP_HDR_SESSION,
                                    &s, 0) == GST_RTSP_OK ) {
        json_object_set_new(rspjs, "session", json_string(s));
    }

    json_object_set_new(rtspjs, "response", rspjs);

    json_object_set_new(js, "rtsp", rtspjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->rtsplog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;
    
error:
    if (rtspjs != NULL) {
        json_decref(rtspjs);
    }
    if (reqjs != NULL) {
        json_decref(reqjs);
    }
    if (rspjs != NULL) {
        json_decref(rspjs);
    }
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputrtspLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogrtspFileCtx *rtsplog_ctx = (LogrtspFileCtx *)output_ctx->data;
    SCFree(rtsplog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputrtspLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogrtspFileCtx *rtsplog_ctx = SCCalloc(1, sizeof(*rtsplog_ctx));
    if (unlikely(rtsplog_ctx == NULL)) {
        return NULL;
    }
    rtsplog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(rtsplog_ctx);
        return NULL;
    }
    output_ctx->data = rtsplog_ctx;
    output_ctx->DeInit = OutputrtspLogDeInitCtxSub;

    SCLogNotice("rtsp log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RTSP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonrtspLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogrtspLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogrtsp.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->rtsplog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonrtspLogThreadDeinit(ThreadVars *t, void *data)
{
    LogrtspLogThread *thread = (LogrtspLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonrtspLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_RTSP, "eve-log", "JsonrtspLog",
        "eve-log.rtsp", OutputrtspLogInitSub, ALPROTO_RTSP,
        JsonrtspLogger, JsonrtspLogThreadInit,
        JsonrtspLogThreadDeinit, NULL);

    SCLogNotice("rtsp JSON logger registered.");
}

#else /* No JSON support. */

void JsonrtspLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON && HAVE_GSTREAMER */
