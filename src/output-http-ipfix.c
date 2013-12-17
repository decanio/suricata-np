/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Implements IPFIX HTTP logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "util-mem.h"

#include "output.h"
#include "output-http-ipfix.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-ipfix.h"

#include "output-ipfix.h"

#ifdef HAVE_IPFIX

/** Default XFF header name */
#define IPFIX_XFF_DEFAULT "X-Forwarded-For"
/** Single XFF IP maximum length */
#define IPFIX_XFF_MAXLEN 46
/** XFF header value minimal length */
#define IPFIX_XFF_CHAIN_MINLEN 7
/** XFF header value maximum length */
#define IPFIX_XFF_CHAIN_MAXLEN 256

typedef struct OutputHttpCtx_ {
    uint32_t flags; /** Store mode */
} OutputHttpCtx;

#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_CUSTOM 2

/* IPFIX definition of the HTTP log record */
static fbInfoElementSpec_t http_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    /* http info */
    { "httpHost",                           0, 0 },
    { "httpGet",                            0, 0 },
    { "httpUserAgent",                      0, 0 },
    { "httpX-Forwarded-For",                0, 0 },
    { "httpContentType",                    0, 0 },
    { "httpReferer",                        0, 0 },
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    { "npulseAppLabel",                     0, 0 },
    { "paddingOctets",                      7, 1 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t http_log_ext_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    /* 5-tuple */
    { "sourceIPv6Address",                  0, SURI_IP6 },
    { "destinationIPv6Address",             0, SURI_IP6 },
    { "sourceIPv4Address",                  0, SURI_IP4 },
    { "destinationIPv4Address",             0, SURI_IP4 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    { "npulseAppLabel",                     0, 0 },
    /* http info */
    { "httpHost",                           0, 0 },
    { "httpGet",                            0, 0 },
    { "httpUserAgent",                      0, 0 },
    { "httpX-Forwarded-For",                0, 0 },
    { "httpContentType",                    0, 0 },
    { "httpReferer",                        0, 0 },
    FB_IESPEC_NULL
};

/* HTTP Metadata Record */
#pragma pack(push, 1)
typedef struct HttpLog_st {
    uint64_t	 AlertMilliseconds;
    fbVarfield_t hostname;
    fbVarfield_t uri;
    fbVarfield_t userAgent;
    fbVarfield_t xff;
    fbVarfield_t contentType;
    fbVarfield_t referer;
    //fbVarfield_t method;
    //fbVarfield_t status;
    //fbVarfield_t redirect;
    //uint64_t     length;

    uint8_t      sourceIPv6Address[16];
    uint8_t      destinationIPv6Address[16];

    uint32_t     sourceIPv4Address;
    uint32_t     destinationIPv4Address;

    uint16_t     sourceTransportPort;
    uint16_t     destinationTransportPort;
    uint8_t      protocolIdentifier;
    uint16_t     npulseAppLabel;
} HttpLog_t;
#pragma pack(pop)

gboolean SetExportTemplate(
    fbInfoModel_t       *fb_model,
    fBuf_t              *fbuf,
    uint16_t            tid,
    GError              **err)
{
    fbSession_t         *session = NULL;
    fbTemplate_t        *tmpl = NULL;

    /* Try to set export template */
    if (fBufSetExportTemplate(fbuf, tid, err)) {
        return TRUE;
    }

    /* Check for error other than missing template */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    /* Okay. We have a missing template. Clear the Teerror and try to load it. */
    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(fb_model);

    SCLogInfo("tid: %x Appending tid: %x\n", tid, (tid & (~SURI_HTTP_BASE_TID)));
    if (!fbTemplateAppendSpecArray(tmpl, http_log_ext_spec,
                                   //(tid & (~SURI_HTTP_BASE_TID)), err))    {
                                   (tid & (~SURI_BASE_TID)), err))    {
        return FALSE;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        SCLogInfo("failed to add external template");
        return FALSE;
    }

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}

/* Retrieves the selected cookie value */
static uint32_t GetCookieValue(uint8_t *rawcookies, uint32_t rawcookies_len, char *cookiename,
                                                        uint8_t **cookievalue) {
    uint8_t *p = rawcookies;
    uint8_t *cn = p; /* ptr to cookie name start */
    uint8_t *cv = NULL; /* ptr to cookie value start */
    while (p < rawcookies + rawcookies_len) {
        if (cv == NULL && *p == '=') {
            cv = p + 1;
        } else if (cv != NULL && (*p == ';' || p == rawcookies + rawcookies_len - 1) ) {
            /* Found end of cookie */
            p++;
            if (strlen(cookiename) == (unsigned int) (cv-cn-1) &&
                        strncmp(cookiename, (char *) cn, cv-cn-1) == 0) {
                *cookievalue = cv;
                return (uint32_t) (p-cv);
            }
            cv = NULL;
            cn = p + 1;
        }
        p++;
    }
    return 0;
}

/* Custom format logging */
static void LogHttpLogCustom(AlertIPFIXThread *aft, htp_tx_t *tx,
                             const struct timeval *ts,
                             char *srcip, Port sp, char *dstip, Port dp)
{
    //LogHttpFileCtx *httplog_ctx = aft->httplog_ctx;
    //LogIPFIXCtx *ipfix_ctx = aft->ipfix_ctx;
#if 0
    uint32_t i;
    uint32_t datalen;
    char buf[128];

    uint8_t *cvalue;
    uint32_t cvalue_len = 0;

    htp_header_t *h_request_hdr;
    htp_header_t *h_response_hdr;

    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *timestamp = SCLocalTime(time, &local_tm);

    for (i = 0; i < httplog_ctx->cf_n; i++) {
        h_request_hdr = NULL;
        h_response_hdr = NULL;
        switch (httplog_ctx->cf_nodes[i]->type){
            case LOG_HTTP_CF_LITERAL:
            /* LITERAL */
                MemBufferWriteString(aft->buffer, "%s", httplog_ctx->cf_nodes[i]->data);
                break;
            case LOG_HTTP_CF_TIMESTAMP:
            /* TIMESTAMP */
                if (httplog_ctx->cf_nodes[i]->data[0] == '\0') {
                    strftime(buf, 62, TIMESTAMP_DEFAULT_FORMAT, timestamp);
                } else {
                    strftime(buf, 62, httplog_ctx->cf_nodes[i]->data, timestamp);
                }
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)buf,strlen(buf));
                break;
            case LOG_HTTP_CF_TIMESTAMP_U:
            /* TIMESTAMP USECONDS */
                snprintf(buf, 62, "%06u", (unsigned int) ts->tv_usec);
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)buf,strlen(buf));
                break;
            case LOG_HTTP_CF_CLIENT_IP:
            /* CLIENT IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)srcip,strlen(srcip));
                break;
            case LOG_HTTP_CF_SERVER_IP:
            /* SERVER IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)dstip,strlen(dstip));
                break;
            case LOG_HTTP_CF_CLIENT_PORT:
            /* CLIENT PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", sp);
                break;
            case LOG_HTTP_CF_SERVER_PORT:
            /* SERVER PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", dp);
                break;
            case LOG_HTTP_CF_REQUEST_METHOD:
            /* METHOD */
                if (tx->request_method != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_method),
                                bstr_len(tx->request_method));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_URI:
            /* URI */
                if (tx->request_uri != NULL) {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(tx->request_uri)) {
                        datalen = bstr_len(tx->request_uri);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_uri),
                                datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_HOST:
            /* HOSTNAME */
                if (tx->request_hostname != NULL)
                {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(tx->parsed_uri->hostname)) {
                        datalen = bstr_len(tx->parsed_uri->hostname);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_hostname),
                                bstr_len(tx->request_hostname));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_PROTOCOL:
            /* PROTOCOL */
                if (tx->request_protocol != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_protocol),
                                    bstr_len(tx->request_protocol));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_HEADER:
            /* REQUEST HEADER */
                if (tx->request_headers != NULL) {
                    h_request_hdr = htp_table_get_c(tx->request_headers, httplog_ctx->cf_nodes[i]->data);
                }
                if (h_request_hdr != NULL) {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(h_request_hdr->value)) {
                        datalen = bstr_len(h_request_hdr->value);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(h_request_hdr->value),
                                    datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_COOKIE:
            /* REQUEST COOKIE */
                if (tx->request_headers != NULL) {
                    h_request_hdr = htp_table_get_c(tx->request_headers, "Cookie");
                    if (h_request_hdr != NULL) {
                        cvalue_len = GetCookieValue((uint8_t *) bstr_ptr(h_request_hdr->value),
                                    bstr_len(h_request_hdr->value), (char *) httplog_ctx->cf_nodes[i]->data,
                                    &cvalue);
                    }
                }
                if (cvalue_len > 0) {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > cvalue_len) {
                        datalen = cvalue_len;
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, cvalue, datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_LEN:
            /* REQUEST LEN */
                MemBufferWriteString(aft->buffer, "%"PRIuMAX"", (uintmax_t)tx->request_message_len);
                break;
            case LOG_HTTP_CF_RESPONSE_STATUS:
            /* RESPONSE STATUS */
                if (tx->response_status != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(tx->response_status),
                                    bstr_len(tx->response_status));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_RESPONSE_HEADER:
            /* RESPONSE HEADER */
                if (tx->response_headers != NULL) {
                    h_response_hdr = htp_table_get_c(tx->response_headers,
                                    httplog_ctx->cf_nodes[i]->data);
                }
                if (h_response_hdr != NULL) {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(h_response_hdr->value)) {
                        datalen = bstr_len(h_response_hdr->value);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(h_response_hdr->value),
                                    datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_RESPONSE_LEN:
            /* RESPONSE LEN */
                MemBufferWriteString(aft->buffer, "%"PRIuMAX"", (uintmax_t)tx->response_message_len);
                break;
            default:
            /* NO MATCH */
                MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                SCLogDebug("No matching parameter %%%c for custom http log.", httplog_ctx->cf_nodes[i]->type);
                break;
        }
    }
    MemBufferWriteString(aft->buffer, "\n");
#endif
}

static void LogHttpLogExtended(AlertIPFIXThread *aft, htp_tx_t *tx)
{
#if 0
    MemBufferWriteString(aft->buffer, " [**] ");

    /* referer */
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = htp_table_get_c(tx->request_headers, "referer");
    }
    if (h_referer != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(h_referer->value),
                       bstr_len(h_referer->value));
    } else {
        MemBufferWriteString(aft->buffer, "<no referer>");
    }
    MemBufferWriteString(aft->buffer, " [**] ");

    /* method */
    if (tx->request_method != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(tx->request_method),
                       bstr_len(tx->request_method));
    }
    MemBufferWriteString(aft->buffer, " [**] ");

    /* protocol */
    if (tx->request_protocol != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(tx->request_protocol),
                       bstr_len(tx->request_protocol));
    } else {
        MemBufferWriteString(aft->buffer, "<no protocol>");
    }
    MemBufferWriteString(aft->buffer, " [**] ");

    /* response status */
    if (tx->response_status != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(tx->response_status),
                       bstr_len(tx->response_status));
        /* Redirect? */
        if ((tx->response_status_number > 300) && ((tx->response_status_number) < 303)) {
            htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
            if (h_location != NULL) {
                MemBufferWriteString(aft->buffer, " => ");

                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                               (uint8_t *)bstr_ptr(h_location->value),
                               bstr_len(h_location->value));
            }
        }
    } else {
        MemBufferWriteString(aft->buffer, "<no status>");
    }

    /* length */
    MemBufferWriteString(aft->buffer, " [**] %"PRIuMAX" bytes", (uintmax_t)tx->response_message_len);
#endif
}

static TmEcode LogHttpLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data,
                                        int ipproto)
{
    SCEnter();

    HttpLog_t rec;
    GError *err = NULL;
    uint16_t tid;
    uint64_t tx_id = 0;
    uint64_t total_txs = 0;
    htp_tx_t *tx = NULL;
    HtpState *htp_state = NULL;
    int tx_progress = 0;
    int tx_progress_done_value_ts = 0;
    int tx_progress_done_value_tc = 0;
    //LogHttpLogThread *aft = (LogHttpLogThread *)data;
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    //LogHttpFileCtx *hlog = aft->httplog_ctx;
    LogIPFIXCtx *ipfix_ctx = aft->ipfix_ctx;
    TmEcode rc = TM_ECODE_OK;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have HTTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_HTTP)
        goto end;

    htp_state = (HtpState *)AppLayerGetProtoStateFromPacket(p);
    if (htp_state == NULL) {
        SCLogDebug("no http state, so no request logging");
        goto end;
    }

    total_txs = AppLayerGetTxCnt(ALPROTO_HTTP, htp_state);
    tx_id = AppLayerTransactionGetLogId(p->flow);
    tx_progress_done_value_ts = AppLayerGetAlstateProgressCompletionStatus(ALPROTO_HTTP, 0);
    tx_progress_done_value_tc = AppLayerGetAlstateProgressCompletionStatus(ALPROTO_HTTP, 1);

    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);

    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                rec.sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                tid = SURI_HTTP_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec.sourceIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_HTTP_BASE_TID | SURI_IP6;
                break;
            default:
                goto end;
        }
        rec.sourceTransportPort = p->sp;
        rec.destinationTransportPort = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                rec.sourceIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                tid = SURI_HTTP_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec.sourceIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_HTTP_BASE_TID | SURI_IP6;
                break;
            default:
                goto end;
        }
        rec.sourceTransportPort = p->dp;
        rec.destinationTransportPort = p->sp;
    }
    rec.protocolIdentifier = IPV4_GET_IPPROTO(p);
    rec.npulseAppLabel = 80;

    for (; tx_id < total_txs; tx_id++)
    {
        tx = AppLayerGetTx(ALPROTO_HTTP, htp_state, tx_id);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging !!");
            continue;
        }

        if (!(((AppLayerParserStateStore *)p->flow->alparser)->id_flags & APP_LAYER_TRANSACTION_EOF)) {
            tx_progress = AppLayerGetAlstateProgress(ALPROTO_HTTP, tx, 0);

            if (tx_progress < tx_progress_done_value_ts)
                break;

            tx_progress = AppLayerGetAlstateProgress(ALPROTO_HTTP, tx, 1);
            if (tx_progress < tx_progress_done_value_tc)
                break;
        }

#ifndef NOMETADATA
        /* hostname */
        if (tx->request_hostname != NULL) {
            rec.hostname.buf = (uint8_t *)bstr_ptr(tx->request_hostname);
            rec.hostname.len = bstr_len(tx->request_hostname);
        } else {
            rec.hostname.buf = (uint8_t *)"<hostname unknown>";
            rec.hostname.len = strlen("<hostname unknown>");
        }

        /* uri */
        if (tx->request_uri != NULL) {
            rec.uri.buf = (uint8_t *)bstr_ptr(tx->request_uri);
            rec.uri.len = bstr_len(tx->request_uri);
        } else {
            rec.uri.len = 0;
        }

        /* user agent */
        htp_header_t *h_user_agent = NULL;
        if (tx->request_headers != NULL) {
            h_user_agent = htp_table_get_c(tx->request_headers, "user-agent");
        }
        if (h_user_agent != NULL) {
            rec.userAgent.buf = (uint8_t *)bstr_ptr(h_user_agent->value);
            rec.userAgent.len = bstr_len(h_user_agent->value);
        } else {
            rec.userAgent.buf = (uint8_t *)"<useragent unknown>";
            rec.userAgent.len = strlen("<useragent unknown>");
        }

        /* x-forwarded-for */
        htp_header_t *h_x_forwarded_for = NULL;
        if (tx->request_headers != NULL) {
            h_x_forwarded_for = htp_table_get_c(tx->request_headers,
                                                IPFIX_XFF_DEFAULT);
        }

        if (h_x_forwarded_for != NULL &&
            bstr_len(h_x_forwarded_for->value) >= IPFIX_XFF_CHAIN_MINLEN &&
            bstr_len(h_x_forwarded_for->value) < IPFIX_XFF_CHAIN_MAXLEN) {
            rec.xff.buf = (uint8_t *)bstr_ptr(h_x_forwarded_for->value);
            rec.xff.len = bstr_len(h_x_forwarded_for->value);
        } else {
            rec.xff.len = 0;
        }

        /* content-type */
        htp_header_t *h_content_type = NULL;
        if(tx->response_headers != NULL) {
            h_content_type = htp_table_get_c(tx->response_headers, "content-type");
        }
        if (h_content_type != NULL) {
            rec.contentType.buf = (uint8_t *)bstr_ptr(h_content_type->value);
            rec.contentType.len = bstr_len(h_content_type->value);
        } else {
            rec.contentType.len = 0;
        }

        /* referer */
        htp_header_t *h_referer = NULL;
        if (tx->request_headers != NULL) {
            h_referer = htp_table_get_c(tx->request_headers, "referer");
        }
        if (h_referer != NULL) {
            //rec.referer.buf = (uint8_t *)bstr_ptr(tx->request_method);
            //rec.referer.len = bstr_len(tx->request_method);
            rec.referer.buf = (uint8_t *)bstr_ptr(h_referer->value);
            rec.referer.len = bstr_len(h_referer->value);
        } else {
            rec.referer.len = 0;
        }
#endif
#ifdef NOTYET
        aft->uri_cnt ++;
#endif

        //SCMutexLock(&hlog->ipfix_ctx->mutex);
        SCMutexLock(&ipfix_ctx->mutex);

        /* set internal template */
        if (!fBufSetInternalTemplate(ipfix_ctx->fbuf, SURI_HTTP_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }

        /* Try to set export template */
        if (ipfix_ctx->fbuf) {
            if (!SetExportTemplate(ipfix_ctx->fb_model, ipfix_ctx->fbuf, tid, &err)) {
                SCMutexUnlock(&ipfix_ctx->mutex);
                SCLogInfo("fBufSetExportTemplate failed");
                return TM_ECODE_FAILED;
            }
        } else {
                SCMutexUnlock(&ipfix_ctx->mutex);
                SCLogInfo("no fbuf");
                return TM_ECODE_FAILED;
        }

        //SCLogInfo("Appending IPFIX record to log");
        /* Now append the record to the buffer */
        if (!fBufAppend(ipfix_ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
            //SCMutexUnlock(&aft->httplog_ctx->mutex);
            SCLogInfo("fBufAppend failed");
            rc = TM_ECODE_FAILED;
            goto error_out;
        }

error_out:
        ipfix_ctx->last_logger = 80;
        SCMutexUnlock(&ipfix_ctx->mutex);

        AppLayerTransactionUpdateLogId(ALPROTO_HTTP, p->flow);
    }

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(rc);

}

TmEcode LogHttpLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data)
{
    return LogHttpLogIPFIXIPWrapper(tv, p, data, AF_INET);
}

TmEcode LogHttpLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data)
{
    return LogHttpLogIPFIXIPWrapper(tv, p, data, AF_INET6);
}

TmEcode OutputHttpIPFIXLog(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        SCReturnInt(LogHttpLogIPFIXIPv4(tv, p, data));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogHttpLogIPFIXIPv6(tv, p, data));
    }

    SCReturnInt(TM_ECODE_OK);
}

void OutputHttpSetTemplates(LogIPFIXCtx *ipfix_ctx)
{
    GError *err = NULL;
    uint16_t tid;

    //if (ipfix_ctx->session && ipfix_ctx->fbuf) {
    if (ipfix_ctx->session) {
        fbInfoModel_t *model = ipfix_ctx->fb_model;

        /* Create the full record template */
        if ((ipfix_ctx->int_http_tmpl = fbTemplateAlloc(model)) == NULL) {
            SCLogInfo("fbTemplateAlloc failed");
            return;
        }
        SCLogInfo("int_http_tmpl: %p", ipfix_ctx->int_http_tmpl);
        /* Create the full record template */
        if ((ipfix_ctx->ext_http_tmpl = fbTemplateAlloc(model)) == NULL) {
            SCLogInfo("fbTemplateAlloc failed");
            return;
        }
        SCLogInfo("ext_http_tmpl: %p", ipfix_ctx->ext_http_tmpl);

        if (!fbTemplateAppendSpecArray(ipfix_ctx->int_http_tmpl, http_log_int_spec, SURI_HTTP_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }
        /* Add the full record template to the session */
        tid = fbSessionAddTemplate(ipfix_ctx->session, TRUE, SURI_HTTP_BASE_TID,
                                   ipfix_ctx->int_http_tmpl, &err);
        if (tid == 0) {
            SCLogInfo("fbSessionAddTemplate failed");
            return;
        }
        if (!fbTemplateAppendSpecArray(ipfix_ctx->ext_http_tmpl, http_log_ext_spec, SURI_HTTP_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }
    }
}

OutputCtx *OutputHttpIPFIXLogInit(ConfNode *conf)
{
    OutputHttpCtx *http_ctx = SCMalloc(sizeof(OutputHttpCtx));
    if (unlikely(http_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    http_ctx->flags = LOG_HTTP_DEFAULT;

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                http_ctx->flags = LOG_HTTP_EXTENDED;
            }
        }
    }
    output_ctx->data = http_ctx;
    output_ctx->DeInit = NULL;

    return output_ctx;
}

#endif
