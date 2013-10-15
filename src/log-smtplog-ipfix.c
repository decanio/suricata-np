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

#include "util-logopenfile.h"

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
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogSmtpFileCtx;

typedef struct LogSmtpLogThread_ {
    LogSmtpFileCtx *smtplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t smtp_cnt;

    MemBuffer *buffer;
} LogSmtpLogThread;

static TmEcode LogSmtpLogIPFIXIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    LogSmtpLogThread *aft = (LogSmtpLogThread *)data;
    LogSmtpFileCtx *hlog = aft->smtplog_ctx;
    char timebuf[64];

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
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }
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

        /* reset */
        MemBufferReset(aft->buffer);

        json_t *js = json_object();
        if (js == NULL)
            SCReturnInt(TM_ECODE_OK);

        json_t *sjs = json_object();
        if (sjs == NULL) {
            free(js);
            SCReturnInt(TM_ECODE_OK);
        }

        /* time & tx */
        json_object_set_new(js, "time", json_string(timebuf));

        /* tuple */
        json_object_set_new(js, "srcip", json_string(srcip));
        json_object_set_new(js, "sp", json_integer(sp));
        json_object_set_new(js, "dstip", json_string(dstip));
        json_object_set_new(js, "dp", json_integer(dp));

        json_object_set_new(sjs, "from", json_string(
                  (char *)((smtp_state->from_line != NULL) ? smtp_state->from_line : "")));
#if 0
        json_object_set_new(sjs, "to", json_string(
                  (char *)((smtp_state->to_line != NULL) ? smtp_state->to_line : "")));
#else
        if (smtp_state->to_line != NULL) {
            json_t *tjs = json_array();
            if (tjs != NULL) {
                char *savep;
                char *p;
                json_t *njs[128];
                int i = 0;
                njs[i] = json_object();
                p = strtok_r((char *)smtp_state->to_line, ",", &savep);
                /*SCLogInfo("first token: \"%s\"", &p[strspn(p, " \t")]);*/
                json_object_set_new(njs[i], "emailaddr", json_string(&p[strspn(p, " \t")]));
                json_array_append(tjs, njs[i++]);
                while ((p = strtok_r(NULL, ",", &savep)) != NULL) {
                    /*SCLogInfo("next token: \"%s\"", &p[strspn(p, " \t")]);*/
                    njs[i] = json_object();
                    json_object_set(njs[i], "emailaddr", json_string(&p[strspn(p, " \t")]));
                    json_array_append(tjs, njs[i++]);
                }
            }
            json_object_set_new(sjs, "to", tjs);
        }
#endif

        if (smtp_state->cc_line != NULL) {
            json_t *cjs = json_array();
            if (cjs != NULL) {
                char *savep;
                char *p;
                json_t *njs[128];
                int i = 0;
                njs[i] = json_object();
                p = strtok_r((char *)smtp_state->cc_line, ",", &savep);
                /*SCLogInfo("first token: \"%s\"", &p[strspn(p, " \t")]);*/
                json_object_set_new(njs[i], "emailaddr", json_string(&p[strspn(p, " \t")]));
                json_array_append(cjs, njs[i++]);
                while ((p = strtok_r(NULL, ",", &savep)) != NULL) {
                    /*SCLogInfo("next token: \"%s\"", &p[strspn(p, " \t")]);*/
                    njs[i] = json_object();
                    json_object_set(njs[i], "emailaddr", json_string(&p[strspn(p, " \t")]));
                    json_array_append(cjs, njs[i++]);
                }
            }
            json_object_set_new(sjs, "cc", cjs);
        }

        json_object_set_new(sjs, "subject", json_string(
                  (char *)((smtp_state->subject_line != NULL) ? smtp_state->subject_line : "")));

        json_t *ajs = NULL;
        if (smtp_state->attachment_count > 0) {
#if 0
            if (smtp_state->attachment_count == 1) {
                ajs = json_object();
                if (ajs != NULL) {
                    int i = 0;
                    SCLogInfo("Adding \"%s\" into array", smtp_state->attachments[i].name);
                    json_object_set_new(ajs, "name",
                        json_string(smtp_state->attachments[i].name));
                    SCFree(smtp_state->attachments[i].name);
                    smtp_state->attachments[i].name = NULL;
                    json_object_set_new(sjs, "attachment", ajs);
                }

            } else {
#else
            {
#endif
                ajs = json_array();
                if (ajs != NULL) {
                    unsigned i;
                    json_t *njs = json_object();;
                    for (i = 0; i < smtp_state->attachment_count; i++) {
                        int r;
                        /*SCLogInfo("Adding \"%s\" into array", smtp_state->attachments[i].name);*/
                        r = json_object_set_new(njs, "name",
                            json_string((char *)smtp_state->attachments[i].name));
                        if (r!=0)
                            /*SCLogInfo("json_object_set_new failed")*/;
                        SCFree(smtp_state->attachments[i].name);
                        smtp_state->attachments[i].name = NULL;
                        /*
                        json_dumpf(njs, stdout, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
                        printf("\n");
                        */
                        json_array_append(ajs, njs);
                    }
                    /*
                    json_dumpf(ajs, stdout, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
                    printf("\n");
                    */
                    json_object_set_new(sjs, "attachment", ajs);
                }
            }
            smtp_state->attachment_count = 0; 
        }

        /* smtp */
        json_object_set_new(js, "smtp", sjs);
        char *s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
        MemBufferWriteString(aft->buffer, "%s", s);
        free(s);
        if (ajs) free(ajs);
        free(sjs);
        free(js);
        if (smtp_state->to_line != NULL) free(smtp_state->to_line);
        if (smtp_state->from_line != NULL) free(smtp_state->from_line);
        if (smtp_state->subject_line != NULL) free(smtp_state->subject_line);
        if (smtp_state->content_type_line != NULL) free(smtp_state->content_type_line);
        if (smtp_state->content_disp_line != NULL) free(smtp_state->content_disp_line);

        smtp_state->data_state = SMTP_DATA_UNKNOWN;

        aft->smtp_cnt++;

        SCMutexLock(&hlog->file_ctx->fp_mutex);
        (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
        fflush(hlog->file_ctx->fp);
        SCMutexUnlock(&hlog->file_ctx->fp_mutex);

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

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
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

    MemBufferFree(aft->buffer);
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

    SCLogInfo("SMTP logger logged %" PRIu32 " requests", aft->smtp_cnt);
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogSmtpLogIPFIXInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_SMTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogSmtpFileCtx *smtplog_ctx = SCMalloc(sizeof(LogSmtpFileCtx));
    if (unlikely(smtplog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(smtplog_ctx, 0x00, sizeof(LogSmtpFileCtx));

    smtplog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(smtplog_ctx);
        return NULL;
    }

    output_ctx->data = smtplog_ctx;
    output_ctx->DeInit = LogSmtpLogIPFIXDeInitCtx;

    SCLogDebug("SMTP log output initialized");

    return output_ctx;
}

static void LogSmtpLogIPFIXDeInitCtx(OutputCtx *output_ctx)
{
    LogSmtpFileCtx *smtplog_ctx = (LogSmtpFileCtx *)output_ctx->data;
    LogFileFreeCtx(smtplog_ctx->file_ctx);
    SCFree(smtplog_ctx);
    SCFree(output_ctx);
}

