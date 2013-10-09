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
 * Implements http logging to IPFIX portion of the engine.
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

#include "output.h"
#include "log-httplog-ipfix.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-logipfix.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "http-ipfix.log"

#define MODULE_NAME "LogHttpLogIPFIX"

#define OUTPUT_BUFFER_SIZE 65535

#ifndef HAVE_IPFIX
#error Need to finish this
#else /* implied we do have IPFIX support */

#include <fixbuf/public.h>
#include <glib.h>

TmEcode LogHttpLogIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogIPFIXIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogIPFIXIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode LogHttpLogIPFIXThreadDeinit(ThreadVars *, void *);
void LogHttpLogIPFIXExitPrintStats(ThreadVars *, void *);
static void LogHttpLogIPFIXDeInitCtx(OutputCtx *);

void TmModuleLogHttpLogIPFIXRegister (void) {
    tmm_modules[TMM_LOGHTTPLOGIPFIX].name = MODULE_NAME;
    tmm_modules[TMM_LOGHTTPLOGIPFIX].ThreadInit = LogHttpLogIPFIXThreadInit;
    tmm_modules[TMM_LOGHTTPLOGIPFIX].Func = LogHttpLogIPFIX;
    tmm_modules[TMM_LOGHTTPLOGIPFIX].ThreadExitPrintStats = LogHttpLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOGIPFIX].ThreadDeinit = LogHttpLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOGIPFIX].RegisterTests = NULL;
    tmm_modules[TMM_LOGHTTPLOGIPFIX].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "http-log-ipfix", LogHttpLogIPFIXInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_HTTP);
}

void TmModuleLogHttpLogIPFIXIPv4Register (void) {
    tmm_modules[TMM_LOGHTTPLOGIPFIX4].name = "LogHttpLogIPFIXIPv4";
    tmm_modules[TMM_LOGHTTPLOGIPFIX4].ThreadInit = LogHttpLogIPFIXThreadInit;
    tmm_modules[TMM_LOGHTTPLOGIPFIX4].Func = LogHttpLogIPFIXIPv4;
    tmm_modules[TMM_LOGHTTPLOGIPFIX4].ThreadExitPrintStats = LogHttpLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOGIPFIX4].ThreadDeinit = LogHttpLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOGIPFIX4].RegisterTests = NULL;
}

void TmModuleLogHttpLogIPFIXIPv6Register (void) {
    tmm_modules[TMM_LOGHTTPLOGIPFIX6].name = "LogHttpLogIPFIXIPv6";
    tmm_modules[TMM_LOGHTTPLOGIPFIX6].ThreadInit = LogHttpLogIPFIXThreadInit;
    tmm_modules[TMM_LOGHTTPLOGIPFIX6].Func = LogHttpLogIPFIXIPv6;
    tmm_modules[TMM_LOGHTTPLOGIPFIX6].ThreadExitPrintStats = LogHttpLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOGIPFIX6].ThreadDeinit = LogHttpLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOGIPFIX6].RegisterTests = NULL;
}

#define LOG_HTTP_MAXN_NODES 64
#define LOG_HTTP_NODE_STRLEN 256
#define LOG_HTTP_NODE_MAXOUTPUTLEN 8192

#define TIMESTAMP_DEFAULT_FORMAT "%b %d, %Y; %H:%M:%S"
#define LOG_HTTP_CF_NONE "-"
#define LOG_HTTP_CF_LITERAL '%'
#define LOG_HTTP_CF_REQUEST_HOST 'h'
#define LOG_HTTP_CF_REQUEST_PROTOCOL 'H'
#define LOG_HTTP_CF_REQUEST_METHOD 'm'
#define LOG_HTTP_CF_REQUEST_URI 'u'
#define LOG_HTTP_CF_REQUEST_TIME 't'
#define LOG_HTTP_CF_REQUEST_HEADER 'i'
#define LOG_HTTP_CF_REQUEST_COOKIE 'C'
#define LOG_HTTP_CF_REQUEST_LEN 'b'
#define LOG_HTTP_CF_RESPONSE_STATUS 's'
#define LOG_HTTP_CF_RESPONSE_HEADER 'o'
#define LOG_HTTP_CF_RESPONSE_LEN 'B'
#define LOG_HTTP_CF_TIMESTAMP 't'
#define LOG_HTTP_CF_TIMESTAMP_U 'z'
#define LOG_HTTP_CF_CLIENT_IP 'a'
#define LOG_HTTP_CF_SERVER_IP 'A'
#define LOG_HTTP_CF_CLIENT_PORT 'p'
#define LOG_HTTP_CF_SERVER_PORT 'P'

typedef struct LogHttpCustomFormatNode_ {
    uint32_t type; /** Node format type. ie: LOG_HTTP_CF_LITERAL, LOG_HTTP_CF_REQUEST_HEADER */
    uint32_t maxlen; /** Maximun length of the data */
    char data[LOG_HTTP_NODE_STRLEN]; /** optional data. ie: http header name */
} LogHttpCustomFormatNode;

typedef struct LogHttpFileCtx_ {
    LogIPFIXCtx *ipfix_ctx;

    uint32_t flags; /** Store mode */
    uint32_t cf_n; /** Total number of custom string format nodes */
    LogHttpCustomFormatNode *cf_nodes[LOG_HTTP_MAXN_NODES]; /** Custom format string nodes */
} LogHttpFileCtx;

#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_CUSTOM 2

typedef struct LogHttpLogIPFIXThread_ {
    LogHttpFileCtx *httplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;

    MemBuffer *buffer;
} LogHttpLogThread;

/* TBD: move these to util-logipfix.h */
#define SURI_HTTP_BASE_TID	0x3100
#define SURI_HTTP_BASIC_TID	0x5001

/* Special dimensions */
#define SURI_IP4		0x0001
#define SURI_IP6		0x0002

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
                                   (tid & (~SURI_HTTP_BASE_TID)), err))    {
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
static void LogHttpLogCustom(LogHttpLogThread *aft, htp_tx_t *tx, const struct timeval *ts,
                                            char *srcip, Port sp, char *dstip, Port dp)
{
    LogHttpFileCtx *httplog_ctx = aft->httplog_ctx;
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
}

static void LogHttpLogExtended(LogHttpLogThread *aft, htp_tx_t *tx)
{
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
}

static TmEcode LogHttpLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
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
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    LogHttpFileCtx *hlog = aft->httplog_ctx;
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
            h_x_forwarded_for = htp_table_get_c(tx->request_headers, "x-forwarded-for");
        }
        if (h_x_forwarded_for != NULL) {
            rec.xff.buf = (uint8_t)bstr_ptr(h_x_forwarded_for->value);
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
            rec.referer.buf = (uint8_t *)bstr_ptr(tx->request_method);
            rec.referer.len = bstr_len(tx->request_method);
        } else {
            rec.referer.len = 0;
        }

        aft->uri_cnt ++;

        SCMutexLock(&hlog->ipfix_ctx->mutex);

        /* Try to set export template */
        if (aft->httplog_ctx->ipfix_ctx->fbuf) {
            if (!SetExportTemplate(aft->httplog_ctx->ipfix_ctx->fb_model, aft->httplog_ctx->ipfix_ctx->fbuf, tid, &err)) {
                SCMutexUnlock(&aft->httplog_ctx->ipfix_ctx->mutex);
                SCLogInfo("fBufSetExportTemplate failed");
                return TM_ECODE_FAILED;
            }
        } else {
                SCMutexUnlock(&aft->httplog_ctx->ipfix_ctx->mutex);
                SCLogInfo("no fbuf");
                return TM_ECODE_FAILED;
        }

        SCLogInfo("Appending IPFIX record to log");
        /* Now append the record to the buffer */
        if (!fBufAppend(aft->httplog_ctx->ipfix_ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
            //SCMutexUnlock(&aft->httplog_ctx->mutex);
            SCLogInfo("fBufAppend failed");
            rc = TM_ECODE_FAILED;
            goto error_out;
        }

error_out:
        SCMutexUnlock(&hlog->ipfix_ctx->mutex);

        AppLayerTransactionUpdateLogId(ALPROTO_HTTP, p->flow);
    }

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(rc);

}

TmEcode LogHttpLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogHttpLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogHttpLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogHttpLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogHttpLogIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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
        SCReturnInt(LogHttpLogIPFIXIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogHttpLogIPFIXIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogHttpLogIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogHttpLogThread *aft = SCMalloc(sizeof(LogHttpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogHttpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->httplog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogHttpLogIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }
#if 0
    LogHttpFileCtx *hlog = aft->httplog_ctx;
    GError *err = NULL;
        SCMutexLock(&hlog->mutex);
        if (aft->httplog_ctx->fbuf) {
            if (!fBufEmit(aft->httplog_ctx->fbuf, &err)) {
                SCLogInfo("fBufEmit failed on exit %s", err);
            }
            /* should use API to free this thing */
            aft->httplog_ctx->fbuf = NULL;
        }
        SCMutexUnlock(&hlog->mutex);
#endif
    SCFree(aft);
    return TM_ECODE_OK;
}

void LogHttpLogIPFIXExitPrintStats(ThreadVars *tv, void *data) {
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("HTTP logger logged %" PRIu32 " requests", aft->uri_cnt);
}

static fbSession_t *
InitExporterSession(fbInfoModel_t *fb_model, uint32_t domain, GError **err)
{
    fbInfoModel_t   *model = fb_model;
    fbTemplate_t    *int_tmpl = NULL;
    fbTemplate_t    *ext_tmpl = NULL;
    fbSession_t     *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* set observation domain */
    fbSessionSetDomain(session, domain);

    /* Create the full record template */
    if ((int_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("int_tmpl: %p", int_tmpl);
    if (!fbTemplateAppendSpecArray(int_tmpl, http_log_int_spec, SURI_HTTP_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }
    /* Add the full record template to the session */
    if (!fbSessionAddTemplate(session, TRUE, SURI_HTTP_BASE_TID, int_tmpl, err)) {
        SCLogInfo("fbSessionAddTemplate failed");
        return NULL;
    }

    /* Create the full record template */
    if ((ext_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("ext_tmpl: %p", ext_tmpl);
    if (!fbTemplateAppendSpecArray(ext_tmpl, http_log_ext_spec, SURI_HTTP_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }

    return session; 
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogHttpLogIPFIXInitCtx(ConfNode *conf)
{
#if 0
    fbConnSpec_t spec;
#endif
    char *log_dir;
    GError *err = NULL;

#if 0
    memset(&spec, 0, sizeof(spec));
#endif

    SCLogInfo("HTTP IPFIX logger initializing");

#if 0
    char *filename = (char *)ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL) {
        const char *transport = ConfNodeLookupChildValue(conf, "transport");
        if (transport == NULL) {
            transport = "udp";
        }
        if (strcmp(transport, "sctp") == 0) {
            spec.transport = FB_SCTP;
        } else if (strcmp(transport, "udp") == 0) {
            spec.transport = FB_UDP;
        } else if (strcmp(transport, "tcp") == 0) {
            spec.transport = FB_TCP;
        }
        const char *host = ConfNodeLookupChildValue(conf, "host");
        if (host == NULL) {
        }
        spec.host = (char *)host;
        const char *ipfix_port = ConfNodeLookupChildValue(conf, "ipfix-port");
        if (ipfix_port == NULL) {
            ipfix_port = "4739";
        }
        spec.svc = (char *)ipfix_port;
    } else {
        /* create the filename to use */
        if (ConfGet("default-log-dir", &log_dir) != 1)
            log_dir = DEFAULT_LOG_DIR;
        filename = SCMalloc(PATH_MAX);
        if (filename == NULL)
            return NULL;
        snprintf(filename, PATH_MAX, "%s/%s", log_dir,
                 ConfNodeLookupChildValue(conf, "filename"));
    }

    SCLogInfo("filename: %s", filename);
#endif
#if 1
    LogIPFIXCtx *ipfix_ctx = LogIPFIXNewCtx();
    if(ipfix_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new ipfix_ctx");
        return NULL;
    }
    if (SCConfLogOpenIPFIX(conf, ipfix_ctx, DEFAULT_LOG_FILENAME) < 0) {
        //LogFileFreeCtx(ipfix_ctx);
        return NULL;
    }
#else
    LogFileCtx* file_ctx = LogFileNewCtx();
    const char *p, *np;
    uint32_t n;
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
#endif

    LogHttpFileCtx *httplog_ctx = SCMalloc(sizeof(LogHttpFileCtx));
    if (unlikely(httplog_ctx == NULL)) {
#if 0
        LogFileFreeCtx(file_ctx);
#endif
        return NULL;
    }
    memset(httplog_ctx, 0x00, sizeof(LogHttpFileCtx));
    //SCMutexInit(&httplog_ctx->ipfix_ctx->mutex, NULL);

    httplog_ctx->ipfix_ctx = ipfix_ctx;
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        goto parsererror;
    }

    output_ctx->data = httplog_ctx;
    output_ctx->DeInit = LogHttpLogIPFIXDeInitCtx;

#if 0
    httplog_ctx->ipfix_ctx->fb_model = fbInfoModelAlloc();
    SCLogInfo("fbInfoModelAlloc %p", httplog_ctx->ipfix_ctx->fb_model);
    if (httplog_ctx->ipfix_ctx->fb_model) {
        fbInfoModelAddElementArray(httplog_ctx->ipfix_ctx->fb_model, info_elements);
    }

    if (filename == NULL) {
        /* Allocate an exporter with connection to the collector */
        httplog_ctx->ipfix_ctx->exporter = fbExporterAllocNet(&spec);
    } else {
        /* Allocate an exporter for the file */
        httplog_ctx->ipfix_ctx->exporter = fbExporterAllocFile(filename);
    }
    SCLogInfo("exporter: %p", httplog_ctx->ipfix_ctx->exporter);
#endif
    /* Create a new session */
    uint32_t domain = 0xbeef; /* TBD??? */
    httplog_ctx->ipfix_ctx->session = InitExporterSession(httplog_ctx->ipfix_ctx->fb_model, domain,
                                               &err);
    SCLogInfo("session: %p", httplog_ctx->ipfix_ctx->session);

    httplog_ctx->ipfix_ctx->fbuf = fBufAllocForExport(httplog_ctx->ipfix_ctx->session, httplog_ctx->ipfix_ctx->exporter);
    SCLogInfo("fBufAllocForExport: %p", httplog_ctx->ipfix_ctx->fbuf);

    if (httplog_ctx->ipfix_ctx->session && httplog_ctx->ipfix_ctx->fbuf) {

        /* write templates */
        fbSessionExportTemplates(httplog_ctx->ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(httplog_ctx->ipfix_ctx->fbuf, SURI_HTTP_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }

    SCLogDebug("HTTP log IPFIX output initialized");

    //SCLogInfo("offset of hostname:  %d", offsetof(HttpLog_t, hostname));

    return output_ctx;

parsererror:
#if 0
    for (n = 0;n < httplog_ctx->cf_n;n++) {
        SCFree(httplog_ctx->cf_nodes[n]);
    }
    LogFileFreeCtx(file_ctx);
#endif
    SCFree(httplog_ctx);
    SCLogError(SC_ERR_INVALID_ARGUMENT,"Syntax error in custom http log format string.");
    return NULL;

}

static void LogHttpLogIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    LogHttpFileCtx *httplog_ctx = (LogHttpFileCtx *)output_ctx->data;
    uint32_t i;
    for (i = 0; i < httplog_ctx->cf_n; i++) {
        SCFree(httplog_ctx->cf_nodes[i]);
    }
#if 1
    if (httplog_ctx->ipfix_ctx->fb_model) {
        GError *err = NULL;
        SCMutexLock(&httplog_ctx->ipfix_ctx->mutex);
        if (httplog_ctx->ipfix_ctx->fbuf) {
            if (!fBufEmit(httplog_ctx->ipfix_ctx->fbuf, &err)) {
                SCLogInfo("fBufEmit failed on exit %s", err);
            }
            /* should use API to free this thing */
            httplog_ctx->ipfix_ctx->fbuf = NULL;
        }
        SCMutexUnlock(&httplog_ctx->ipfix_ctx->mutex);

        fbInfoModelFree(httplog_ctx->ipfix_ctx->fb_model);
    }
#else
    LogFileFreeCtx(httplog_ctx->file_ctx);
#endif
    SCFree(httplog_ctx);
    SCFree(output_ctx);
}

#endif
