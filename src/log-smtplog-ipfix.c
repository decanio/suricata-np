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
#include "log-smtplog-ipfix.h"
#include "app-layer-smtp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logipfix.h"

#define DEFAULT_LOG_FILENAME "smtp-ipfix.log"

#define MODULE_NAME "LogSmtpLogIpfix"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

TmEcode LogSmtpLogIPFIX (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogSmtpLogIPFIXIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogSmtpLogIPFIXIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogSmtpLogIPFIXThreadInit(ThreadVars *, void *, void **);
TmEcode LogSmtpLogIPFIXThreadDeinit(ThreadVars *, void *);
void LogSmtpLogIPFIXExitPrintStats(ThreadVars *, void *);
static void LogSmtpLogIPFIXDeInitCtx(OutputCtx *);

void TmModuleLogSmtpLogIPFIXRegister (void) {
    tmm_modules[TMM_LOGSMTPLOGIPFIX].name = MODULE_NAME;
    tmm_modules[TMM_LOGSMTPLOGIPFIX].ThreadInit = LogSmtpLogIPFIXThreadInit;
    tmm_modules[TMM_LOGSMTPLOGIPFIX].Func = LogSmtpLogIPFIX;
    tmm_modules[TMM_LOGSMTPLOGIPFIX].ThreadExitPrintStats = LogSmtpLogIPFIXExitPrintStats;
    tmm_modules[TMM_LOGSMTPLOGIPFIX].ThreadDeinit = LogSmtpLogIPFIXThreadDeinit;
    tmm_modules[TMM_LOGSMTPLOGIPFIX].RegisterTests = NULL;
    tmm_modules[TMM_LOGSMTPLOGIPFIX].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "smtp-log-ipfix", LogSmtpLogIPFIXInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_SMTP);
    SCLogInfo("registered %s", MODULE_NAME);
}

typedef struct LogSmtpFileCtx_ {
    LogIPFIXCtx *ipfix_ctx;
    uint32_t flags; /** Store mode */
} LogSmtpFileCtx;

typedef struct LogSmtpLogThread_ {
    LogSmtpFileCtx *smtplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t smtp_cnt;

} LogSmtpLogThread;

/* TBD: move these to util-logipfix.h */
#define SURI_SMTP_BASE_TID      0x3400

/* Special dimensions */
#define SURI_IP4		0x0001
#define SURI_IP6		0x0002

/* IPFIX definition of the SMTP log record */
static fbInfoElementSpec_t smtp_log_int_spec[] = {
    /* Alert Millisecond (epoch) (native time) */
    { "alertMilliseconds",                  0, 0 },
    { "smtpFrom",                           0, 0 },
    { "smtpSubject",                        0, 0 },
#if 1
    { "basicList",                          0, 0 },
#else
    { "smtpTo",                        0, 0 },
#endif
    /* 5-tuple */
    { "sourceIPv6Address",                  0, 0 },
    { "destinationIPv6Address",             0, 0 },
    { "sourceIPv4Address",                  0, 0 },
    { "destinationIPv4Address",             0, 0 },
    { "sourceTransportPort",                0, 0 },
    { "destinationTransportPort",           0, 0 },
    { "protocolIdentifier",                 0, 0 },
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
    /* smtp info */
    { "smtpFrom",                           0, 0 },
    { "smtpSubject",                        0, 0 },
#if 1
    { "basicList",                        0, 0 },
#else
    { "smtpTo",                        0, 0 },
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

    /* Okay. We have a missing template. Clear the Teerror and try to load it. */
    g_clear_error(err);
    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(fb_model);

    //SCLogInfo("tid: %x Appending tid: %x\n", tid, (tid & (~SURI_TLS_BASE_TID)));
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

static TmEcode LogSmtpLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();
    SmtpLog_t rec;
    GError *err = NULL;
    uint16_t tid;
    LogSmtpLogThread *aft = (LogSmtpLogThread *)data;
    LogSmtpFileCtx *slog = aft->smtplog_ctx;

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
                        fbInfoModelGetElementByName(slog->ipfix_ctx->fb_model, "smtpTo"), total);
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

        SCMutexLock(&slog->ipfix_ctx->mutex);

        /* Try to set export template */
        if (slog->ipfix_ctx->fbuf) {
            if (!SetExportTemplate(slog->ipfix_ctx->fb_model, slog->ipfix_ctx->fbuf, tid, &err)) {
                SCMutexUnlock(&slog->ipfix_ctx->mutex);
                SCLogInfo("fBufSetExportTemplate failed");
                goto end;
            }
        } else {
            SCMutexUnlock(&slog->ipfix_ctx->mutex);
            goto end;
        }

        //SCLogInfo("Appending IPFIX record to log");
        fbVarfield_t *f = (fbVarfield_t*)fbBasicListGetDataPtr(&(rec.smtpTo));
        SCLogInfo("Appending IPFIX to log \"%s\" (%d)", f->buf, f->len);
        /* Now append the record to the buffer */
        if (!fBufAppend(slog->ipfix_ctx->fbuf, (uint8_t *)&rec, sizeof(rec), &err)) {
            //SCMutexUnlock(&aft->httplog_ctx->mutex);
            SCLogInfo("fBufAppend failed");
        }

        SCMutexUnlock(&slog->ipfix_ctx->mutex);
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

TmEcode LogSmtpLogIPFIXIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogSmtpLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogSmtpLogIPFIXIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogSmtpLogIPFIXIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogSmtpLogIPFIX (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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
        int r  = LogSmtpLogIPFIXIPv4(tv, p, data, pq, postpq);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = LogSmtpLogIPFIXIPv6(tv, p, data, pq, postpq);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogSmtpLogIPFIXThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogSmtpLogThread *aft = SCMalloc(sizeof(LogSmtpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogSmtpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for SMTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->smtplog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogSmtpLogIPFIXThreadDeinit(ThreadVars *t, void *data)
{
    LogSmtpLogThread *aft = (LogSmtpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(LogSmtpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogSmtpLogIPFIXExitPrintStats(ThreadVars *tv, void *data) {
    LogSmtpLogThread *aft = (LogSmtpLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("SMTP IPFIX logger logged %" PRIu32 " requests", aft->smtp_cnt);
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
    if (!fbTemplateAppendSpecArray(int_tmpl, smtp_log_int_spec, SURI_SMTP_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }
    /* Add the full record template to the session */
    if (!fbSessionAddTemplate(session, TRUE, SURI_SMTP_BASE_TID, int_tmpl, err)) {
        SCLogInfo("fbSessionAddTemplate failed");
        return NULL;
    }

    /* Create the full record template */
    if ((ext_tmpl = fbTemplateAlloc(model)) == NULL) {
        SCLogInfo("fbTemplateAlloc failed");
        return NULL;
    }
    SCLogInfo("ext_tmpl: %p", ext_tmpl);
    if (!fbTemplateAppendSpecArray(ext_tmpl, smtp_log_ext_spec, SURI_SMTP_BASE_TID, err)) {
        SCLogInfo("fbTemplateAppendSpecArray failed");
        return NULL;
    }

    return session; 
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogSmtpLogIPFIXInitCtx(ConfNode *conf)
{
    GError *err = NULL;

    SCLogInfo("SMTP IPFIX logger initializing");

    LogIPFIXCtx *ipfix_ctx = LogIPFIXNewCtx();
    if  (ipfix_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "couldn't create new ipfix_ctx");
        return NULL;
    }
    if (SCConfLogOpenIPFIX(conf, ipfix_ctx, DEFAULT_LOG_FILENAME) < 0) {
        return NULL;
    }
    LogSmtpFileCtx *smtplog_ctx = SCMalloc(sizeof(LogSmtpFileCtx));
    if (unlikely(smtplog_ctx == NULL)) {
        return NULL;
    }
    memset(smtplog_ctx, 0x00, sizeof(LogSmtpFileCtx));

    smtplog_ctx->ipfix_ctx = ipfix_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(smtplog_ctx);
        return NULL;
    }

    /* Create a new session */
    uint32_t domain = 0xbeef; /* TBD??? */
    smtplog_ctx->ipfix_ctx->session = InitExporterSession(smtplog_ctx->ipfix_ctx->fb_model, domain,
                                               &err);
    SCLogInfo("session: %p", smtplog_ctx->ipfix_ctx->session);

    smtplog_ctx->ipfix_ctx->fbuf = fBufAllocForExport(smtplog_ctx->ipfix_ctx->session, smtplog_ctx->ipfix_ctx->exporter);
    SCLogInfo("fBufAllocForExport: %p", smtplog_ctx->ipfix_ctx->fbuf);

    if (smtplog_ctx->ipfix_ctx->session && smtplog_ctx->ipfix_ctx->fbuf) {

        /* write templates */
        fbSessionExportTemplates(smtplog_ctx->ipfix_ctx->session, &err);

        /* set internal template */
        if (!fBufSetInternalTemplate(smtplog_ctx->ipfix_ctx->fbuf, SURI_SMTP_BASE_TID, &err)) {
            SCLogInfo("fBufSetInternalTemplate failed");
        }
    }

    output_ctx->data = smtplog_ctx;
    output_ctx->DeInit = LogSmtpLogIPFIXDeInitCtx;

    SCLogDebug("SMTP IPFIX log output initialized");

    return output_ctx;
}

static void LogSmtpLogIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    LogSmtpFileCtx *smtplog_ctx = (LogSmtpFileCtx *)output_ctx->data;
    SCFree(smtplog_ctx);
    SCFree(output_ctx);
}

