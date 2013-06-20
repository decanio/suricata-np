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
 * Implements smtp logging portion of the engine.
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
#include "log-smtplog.h"
#include "app-layer-smtp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define DEFAULT_SMTP_SYSLOG_FACILITY_STR       "local0"
#define DEFAULT_SMTP_SYSLOG_FACILITY           LOG_LOCAL0
#define DEFAULT_SMTP_SYSLOG_LEVEL              LOG_INFO

#ifndef OS_WIN32
static int smtp_syslog_level = DEFAULT_SMTP_SYSLOG_LEVEL;
#endif
#endif

#define DEFAULT_LOG_FILENAME "smtp.log"

#define MODULE_NAME "LogSmtpLog"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

TmEcode LogSmtpLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogSmtpLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogSmtpLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogSmtpLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogSmtpLogThreadDeinit(ThreadVars *, void *);
void LogSmtpLogExitPrintStats(ThreadVars *, void *);
static void LogSmtpLogDeInitCtx(OutputCtx *);

void TmModuleLogSmtpLogRegister (void) {
    tmm_modules[TMM_LOGSMTPLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGSMTPLOG].ThreadInit = LogSmtpLogThreadInit;
    tmm_modules[TMM_LOGSMTPLOG].Func = LogSmtpLog;
    tmm_modules[TMM_LOGSMTPLOG].ThreadExitPrintStats = LogSmtpLogExitPrintStats;
    tmm_modules[TMM_LOGSMTPLOG].ThreadDeinit = LogSmtpLogThreadDeinit;
    tmm_modules[TMM_LOGSMTPLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGSMTPLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "smtp-log", LogSmtpLogInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_SMTP);
    SCLogInfo("registered %s", MODULE_NAME);
}

typedef struct LogSmtpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogSmtpFileCtx;

#define LOG_SMTP_DEFAULT 0
#define LOG_SMTP_JSON 1        /* JSON output */
#define LOG_SMTP_JSON_SYSLOG 2 /* JSON output via syslog */

typedef struct LogSmtpLogThread_ {
    LogSmtpFileCtx *smtplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t smtp_cnt;

    MemBuffer *buffer;
} LogSmtpLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static TmEcode LogSmtpLogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
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
    if (smtp_state->data_state == 6) {
        SCLogInfo("SMTP LOG TO: \"%s\" FROM: \"%s\" SUBJECT \"%s\"",
                  (char *)((smtp_state->to_line != NULL) ? smtp_state->to_line : ""),
                  (char *)((smtp_state->from_line != NULL) ? smtp_state->from_line : ""),
                  (char *)((smtp_state->subject_line != NULL) ? smtp_state->subject_line : ""));

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
        json_object_set_new(sjs, "to", json_string(
                  (char *)((smtp_state->to_line != NULL) ? smtp_state->to_line : "")));
        json_object_set_new(sjs, "subject", json_string(
                  (char *)((smtp_state->subject_line != NULL) ? smtp_state->subject_line : "")));

        /* smtp */
        json_object_set_new(js, "smtp", sjs);
        char *s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
        MemBufferWriteString(aft->buffer, "%s", s);
        free(s);
        free(sjs);
        free(js);

        smtp_state->data_state = 0;

        aft->smtp_cnt++;

        SCMutexLock(&hlog->file_ctx->fp_mutex);
#ifdef HAVE_LIBJANSSON
        if (hlog->flags & LOG_SMTP_JSON_SYSLOG) {
            syslog(smtp_syslog_level, "%s", (char *)aft->buffer->buffer);
        } else {
            if (hlog->flags & LOG_SMTP_JSON) {
                MemBufferWriteString(aft->buffer, "\n");
            }
#endif
            (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
            fflush(hlog->file_ctx->fp);
#ifdef HAVE_LIBJANSSON
        }
#endif
        SCMutexUnlock(&hlog->file_ctx->fp_mutex);

    }
end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogSmtpLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogSmtpLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogSmtpLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogSmtpLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogSmtpLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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
        int r  = LogSmtpLogIPv4(tv, p, data, pq, postpq);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = LogSmtpLogIPv6(tv, p, data, pq, postpq);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogSmtpLogThreadInit(ThreadVars *t, void *initdata, void **data)
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

TmEcode LogSmtpLogThreadDeinit(ThreadVars *t, void *data)
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

void LogSmtpLogExitPrintStats(ThreadVars *tv, void *data) {
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
OutputCtx *LogSmtpLogInitCtx(ConfNode *conf)
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

#ifdef HAVE_LIBJANSSON
    const char *json = ConfNodeLookupChildValue(conf, "json");
    if (json) {
        if (strcmp(json, "syslog") == 0) {
            smtplog_ctx->flags |= (LOG_SMTP_JSON | LOG_SMTP_JSON_SYSLOG);
        } else if (ConfValIsTrue(json)) {
            smtplog_ctx->flags |= LOG_SMTP_JSON;
        }
    }
#endif

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(smtplog_ctx);
        return NULL;
    }

    output_ctx->data = smtplog_ctx;
    output_ctx->DeInit = LogSmtpLogDeInitCtx;

    SCLogDebug("SMTP log output initialized");

    return output_ctx;
}

static void LogSmtpLogDeInitCtx(OutputCtx *output_ctx)
{
    LogSmtpFileCtx *smtplog_ctx = (LogSmtpFileCtx *)output_ctx->data;
    LogFileFreeCtx(smtplog_ctx->file_ctx);
    SCFree(smtplog_ctx);
    SCFree(output_ctx);
}

