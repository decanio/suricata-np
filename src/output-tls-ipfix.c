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
 * Implements IPFIX TLS logging portion of the engine.
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
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-ipfix.h"
#include "util-crypt.h"
#include "util-time.h"

#include "output-ipfix.h"

#ifdef HAVE_IPFIX

/* IPFIX definition of the TLS log record */
static fbInfoElementSpec_t tls_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    { "tlsSubject",                         0, 0 },
    { "tlsIssuerDn",                        0, 0 },
    { "tlsFingerprint",                     0, 0 },
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    { "npulseAppLabel",                     0, 0 },
    { "tlsVersion",                         0, 0 },
    FB_IESPEC_NULL
};
static fbInfoElementSpec_t tls_log_ext_spec[] = {
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
    /* tls info */
    { "tlsSubject",                         0, 0 },
    { "tlsIssuerDn",                        0, 0 },
    { "tlsFingerprint",                     0, 0 },
    { "tlsVersion",                         0, 0 },
    FB_IESPEC_NULL
};

/* TLS Metadata Record */
#pragma pack(push, 1)
typedef struct TlsLog_st {
    uint64_t	 AlertMilliseconds;
    fbVarfield_t tlsSubject;
    fbVarfield_t tlsIssuerDn;
    fbVarfield_t tlsFingerprint;

    uint8_t      sourceIPv6Address[16];
    uint8_t      destinationIPv6Address[16];

    uint32_t     sourceIPv4Address;
    uint32_t     destinationIPv4Address;

    uint16_t     sourceTransportPort;
    uint16_t     destinationTransportPort;
    uint8_t      protocolIdentifier;
    uint16_t     npulseAppLabel;
    uint16_t     tlsVersion;
} TlsLog_t;
#pragma pack(pop)

static gboolean
SetExportTemplate(
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

    /* Okay. We have a missing template. Clear the error and try to load it. */
    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(fb_model);

    if (!fbTemplateAppendSpecArray(tmpl, tls_log_ext_spec,
                                   (tid & (~SURI_TLS_BASE_TID)), err))    {
        return FALSE;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        SCLogInfo("failed to add external template");
        return FALSE;
    }

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}

static int GetIPInformation(Packet *p, TlsLog_t *rec, uint16_t *tid, int ipproto)
{
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                rec->sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                rec->destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                *tid = SURI_TLS_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec->sourceIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec->sourceIPv6Address));
                memcpy(rec->destinationIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec->destinationIPv6Address));
                *tid = SURI_TLS_BASE_TID | SURI_IP6;
                break;
            default:
                return 0;
        }
        rec->sourceTransportPort = p->sp;
        rec->destinationTransportPort = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                rec->sourceIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                rec->destinationIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                *tid = SURI_TLS_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec->sourceIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec->sourceIPv6Address));
                memcpy(rec->destinationIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec->destinationIPv6Address));
                *tid = SURI_TLS_BASE_TID | SURI_IP6;
                break;
            default:
                return 0;
        }
        rec->sourceTransportPort = p->dp;
        rec->destinationTransportPort = p->sp;
    }
    rec->protocolIdentifier = IPV4_GET_IPPROTO(p);
    rec->npulseAppLabel = 443;
    return 1;
}

static TmEcode LogTlsLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data,
                                       int ipproto)
{

    SCEnter();
    TlsLog_t rec;
    GError *err= NULL;
    uint16_t tid;
    AlertIPFIXThread *aft = (AlertIPFIXThread *) data;
    LogIPFIXCtx *ipfix_ctx = aft->ipfix_ctx;

    /* no flow, no tls state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have TLS state or not */
    FLOWLOCK_WRLOCK(p->flow);
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_TLS)
        goto end;

    SSLState *ssl_state = (SSLState *) AppLayerGetProtoStateFromPacket(p);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto end;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL || ssl_state->server_connp.cert0_subject == NULL)
        goto end;

    if (AppLayerTransactionGetLogId(p->flow) != 0) {
        goto end;
    }

    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);
    if (!GetIPInformation(p, &rec, &tid, ipproto)) {
        goto end;
    }
    rec.tlsVersion = ssl_state->server_connp.version;
    if (ssl_state->server_connp.cert0_fingerprint != NULL) {
        rec.tlsFingerprint.buf = (uint8_t *)ssl_state->server_connp.cert0_fingerprint;
        rec.tlsFingerprint.len = strlen(ssl_state->server_connp.cert0_fingerprint);
    } else {
        rec.tlsFingerprint.len = 0;
    }
    if (ssl_state->server_connp.cert0_subject != NULL) {
        rec.tlsSubject.buf = (uint8_t *)ssl_state->server_connp.cert0_subject;
        rec.tlsSubject.len = strlen(ssl_state->server_connp.cert0_subject);
    } else {
        rec.tlsSubject.len = 0;
    }
    if (ssl_state->server_connp.cert0_issuerdn != NULL) {
        rec.tlsIssuerDn.buf = (uint8_t *)ssl_state->server_connp.cert0_issuerdn;
        rec.tlsIssuerDn.len = strlen(ssl_state->server_connp.cert0_issuerdn);
    } else {
        rec.tlsIssuerDn.len = 0;
    }

    AppLayerTransactionUpdateLogId(ALPROTO_TLS, p->flow);

    aft->tls_cnt ++;

    SCMutexLock(&ipfix_ctx->mutex);

    /* Try to set export template */
    if (ipfix_ctx->fbuf) {
        if (!SetExportTemplate(ipfix_ctx->fb_model, ipfix_ctx->fbuf, tid, &err)) {
            SCMutexUnlock(&ipfix_ctx->mutex);
            SCLogInfo("fBufSetExportTemplate failed");
            goto end;
        }
    } else {
        SCMutexUnlock(&ipfix_ctx->mutex);
        goto end;
    }

    /* Now append the record to the buffer */
    if (!fBufAppend(ipfix_ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
        SCLogInfo("fBufAppend failed");
    }

    SCMutexUnlock(&ipfix_ctx->mutex);

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);

}

TmEcode LogTlsLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data)
{
    return LogTlsLogIPFIXIPWrapper(tv, p, data, AF_INET);
}

TmEcode LogTlsLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data)
{
    return LogTlsLogIPFIXIPWrapper(tv, p, data, AF_INET6);
}

TmEcode OutputTlsIPFIXLog(ThreadVars *tv, Packet *p, void *data)
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
        SCReturnInt(LogTlsLogIPFIXIPv4(tv, p, data));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogTlsLogIPFIXIPv6(tv, p, data));
    }

    SCReturnInt(TM_ECODE_OK);
}

void OutputTlsSetTemplates(LogIPFIXCtx *ipfix_ctx)
{
    GError *err = NULL;

    if (ipfix_ctx->session && ipfix_ctx->fbuf) {

        if (!fbTemplateAppendSpecArray(ipfix_ctx->int_tmpl, tls_log_int_spec, SURI_TLS_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }
        /* Add the full record template to the session */
        if (!fbSessionAddTemplate(ipfix_ctx->session, TRUE, SURI_TLS_BASE_TID, ipfix_ctx->int_tmpl, &err)) {
            SCLogInfo("fbSessionAddTemplate failed");
            return;
        }
        if (!fbTemplateAppendSpecArray(ipfix_ctx->ext_tmpl, tls_log_ext_spec, SURI_TLS_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }

        /* write templates */
        fbSessionExportTemplates(ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(ipfix_ctx->fbuf, SURI_TLS_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }
}

#endif /* HAVE_IPFIX */
