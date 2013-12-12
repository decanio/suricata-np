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
 * Implements smtp IPFIX logging portion of the engine.
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
//#include "log-smtplog-ipfix.h"
#include "app-layer-smtp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-ipfix.h"

#include "output-ipfix.h"

#ifdef HAVE_IPFIX

/* IPFIX definition of the SMTP log record */
static fbInfoElementSpec_t smtp_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    { "smtpFrom",                           0, 0 },
    { "smtpSubject",                        0, 0 },
#if 1
    { "basicList",                          0, 0 },
#else
    { "smtpTo",                             0, 0 },
#endif
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
    { "npulseAppLabel",                     0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t smtp_to_int_spec[] = {
    { "smtpTo",                        0, 0 },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t smtp_log_ext_spec[] = {
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
    /* smtp info */
    { "smtpFrom",                           0, 0 },
    { "smtpSubject",                        0, 0 },
#if 1
    { "basicList",                          0, 0 },
#else
    { "smtpTo",                             0, 0 },
#endif
    FB_IESPEC_NULL
};

/* SMTP Metadata Record */
#pragma pack(push, 1)
typedef struct SmtpLog_st {
    uint64_t	 AlertMilliseconds;
    fbVarfield_t smtpFrom;
    fbVarfield_t smtpSubject;
#if 1
    fbBasicList_t smtpTo;
#else
    fbVarfield_t smtpTo;
#endif

    uint8_t      sourceIPv6Address[16];
    uint8_t      destinationIPv6Address[16];

    uint32_t     sourceIPv4Address;
    uint32_t     destinationIPv4Address;

    uint16_t     sourceTransportPort;
    uint16_t     destinationTransportPort;
    uint8_t      protocolIdentifier;
    uint16_t     npulseAppLabel;
} SmtpLog_t;
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

    if (!fbTemplateAppendSpecArray(tmpl, smtp_log_ext_spec,
                                   (tid & (~SURI_SMTP_BASE_TID)), err))    {
        return FALSE;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, err)) {
        SCLogInfo("failed to add external template");
        return FALSE;
    }

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}

static TmEcode LogSmtpLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data,
                                        int ipproto)
{
    SCEnter();
    SmtpLog_t rec;
    GError *err = NULL;
    uint16_t tid;
    AlertIPFIXThread *aft = (AlertIPFIXThread *)data;
    LogIPFIXCtx *ipfix_ctx = aft->ipfix_ctx;

    /* no flow, no smtp state */
    if (p->flow == NULL) {
        SCLogDebug("no flow");
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have SMTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_SMTP) {
        SCLogDebug("proto not ALPROTO_SMTP: %u", proto);
        goto end;
    }
    SMTPState *smtp_state = (SMTPState *)AppLayerGetProtoStateFromPacket(p);
    if (smtp_state == NULL) {
        SCLogDebug("no smtp state, so no request logging");
        goto end;
    }
    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    rec.AlertMilliseconds = (p->ts.tv_sec * 1000) + (p->ts.tv_usec / 1000);

    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
                rec.sourceIPv4Address = ntohl(GET_IPV4_SRC_ADDR_U32(p));
                rec.destinationIPv4Address = ntohl(GET_IPV4_DST_ADDR_U32(p));
                tid = SURI_SMTP_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec.sourceIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_SMTP_BASE_TID | SURI_IP6;
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
                tid = SURI_SMTP_BASE_TID | SURI_IP4;
                break;
            case AF_INET6:
                memcpy(rec.sourceIPv6Address, GET_IPV6_DST_ADDR(p),
                       sizeof(rec.sourceIPv6Address));
                memcpy(rec.destinationIPv6Address, GET_IPV6_SRC_ADDR(p),
                       sizeof(rec.destinationIPv6Address));
                tid = SURI_SMTP_BASE_TID | SURI_IP6;
                break;
            default:
                goto end;
        }
        rec.sourceTransportPort = p->dp;
        rec.destinationTransportPort = p->sp;
    }
    rec.protocolIdentifier = IPV4_GET_IPPROTO(p);
    rec.npulseAppLabel = 25;

    if (smtp_state->data_state == SMTP_DATA_END) {
        /* 
        SCLogInfo("SMTP LOG TO: \"%s\" FROM: \"%s\" SUBJECT \"%s\"",
                  (char *)((smtp_state->to_line != NULL) ? smtp_state->to_line : ""),
                  (char *)((smtp_state->from_line != NULL) ? smtp_state->from_line : ""),
                  (char *)((smtp_state->subject_line != NULL) ? smtp_state->subject_line : ""));
        if (smtp_state->content_type_line) {
            SCLogInfo("SMTP LOG TYPE: \"%s\"",
                  (char *)((smtp_state->content_type_line != NULL) ? smtp_state->content_type_line : ""));
        }
        if (smtp_state->content_disp_line) {
            SCLogInfo("SMTP LOG DISP: \"%s\"",
                  (char *)((smtp_state->content_disp_line != NULL) ? smtp_state->content_disp_line : ""));
        }
        */

        if (smtp_state->from_line != NULL) {
            rec.smtpFrom.buf = (uint8_t *)smtp_state->from_line;
            rec.smtpFrom.len = strlen(smtp_state->from_line);
        } else {
            rec.smtpFrom.len = 0;
        }
        if (smtp_state->subject_line != NULL) {
            rec.smtpSubject.buf = (uint8_t *)smtp_state->subject_line;
            rec.smtpSubject.len = strlen(smtp_state->subject_line);
        } else {
            rec.smtpSubject.len = 0;
        }
        char *to_line = NULL;
        if (smtp_state->to_line != NULL) {
#if 1
            fbVarfield_t *myVarfield  = NULL;
            char *savep;
            char *p;
            to_line = strdup(smtp_state->to_line);
            int total = 1;
            p = strtok_r(to_line, ",", &savep);
            myVarfield = (fbVarfield_t*)fbBasicListInit(&(rec.smtpTo), 0, 
                        fbInfoModelGetElementByName(ipfix_ctx->fb_model, "smtpTo"), total);
            myVarfield->buf = p;
            myVarfield->len = strlen(p);
            SCLogInfo("TO: \"%s\" (%d)", myVarfield->buf, myVarfield->len);
#if 1
            while ((p = strtok_r(NULL, ",", &savep)) != NULL) {
                myVarfield = (fbVarfield_t*)fbBasicListAddNewElements(&(rec.smtpTo), 1);
                myVarfield[total].buf = p;
                myVarfield[total].len = strlen(p);
                ++total;
            }
#endif
            //SCLogInfo("SMTP TO: field count %d", total);
            //free(to_line);
#else
            rec.smtpTo.buf = (uint8_t *)smtp_state->to_line;
            rec.smtpTo.len = strlen(smtp_state->to_line);
#endif
        } else {
#if 1
#else
            rec.smtpTo.len = 0;
#endif
        }

        aft->smtp_cnt++;

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

        //SCLogInfo("Appending IPFIX record to log");
        fbVarfield_t *f = (fbVarfield_t*)fbBasicListGetDataPtr(&(rec.smtpTo));
        SCLogInfo("Appending IPFIX to log \"%s\" (%d)", f->buf, f->len);
        /* Now append the record to the buffer */
        if (!fBufAppend(ipfix_ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
            //SCMutexUnlock(&aft->httplog_ctx->mutex);
            SCLogInfo("fBufAppend failed");
        }

        SCMutexUnlock(&ipfix_ctx->mutex);
        if (to_line) free(to_line);

        if (AppLayerTransactionUpdateLogId(ALPROTO_SMTP, p->flow) == 1) {
            if (smtp_state->to_line != NULL) free(smtp_state->to_line);
            if (smtp_state->from_line != NULL) free(smtp_state->from_line);
            if (smtp_state->subject_line != NULL) free(smtp_state->subject_line);
            if (smtp_state->content_type_line != NULL) free(smtp_state->content_type_line);
            if (smtp_state->content_disp_line != NULL) free(smtp_state->content_disp_line);
            smtp_state->data_state = SMTP_DATA_UNKNOWN;
        }

    }
end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode LogSmtpLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data)
{
    return LogSmtpLogIPFIXIPWrapper(tv, p, data, AF_INET);
}

static TmEcode LogSmtpLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data)
{
    return LogSmtpLogIPFIXIPWrapper(tv, p, data, AF_INET6);
}

TmEcode OutputSmtpIPFIXLog (ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    /* no flow, no smtp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        int r  = LogSmtpLogIPFIXIPv4(tv, p, data);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = LogSmtpLogIPFIXIPv6(tv, p, data);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

void OutputSmtpSetTemplates(LogIPFIXCtx *ipfix_ctx)
{
    GError *err = NULL;

    if (ipfix_ctx->session && ipfix_ctx->fbuf) {

        if (!fbTemplateAppendSpecArray(ipfix_ctx->int_tmpl, smtp_log_int_spec, SURI_SMTP_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }
        /* Add the full record template to the session */
        if (!fbSessionAddTemplate(ipfix_ctx->session, TRUE, SURI_SMTP_BASE_TID, ipfix_ctx->int_tmpl, &err)) {
            SCLogInfo("fbSessionAddTemplate failed");
            return;
        }
        if (!fbTemplateAppendSpecArray(ipfix_ctx->ext_tmpl, smtp_log_ext_spec, SURI_SMTP_BASE_TID, &err)) {
            SCLogInfo("fbTemplateAppendSpecArray failed");
            return;
        }

        /* write templates */
        fbSessionExportTemplates(ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(ipfix_ctx->fbuf, SURI_SMTP_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }
}

#endif /* HAVE_IPFIX */
