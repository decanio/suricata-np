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
 * Implements ftp logging portion of the engine.
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
#include "log-ftplog.h"
#include "app-layer-ftp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define DEFAULT_FTP_SYSLOG_FACILITY_STR       "local0"
#define DEFAULT_FTP_SYSLOG_FACILITY           LOG_LOCAL0
#define DEFAULT_FTP_SYSLOG_LEVEL              LOG_INFO

#ifndef OS_WIN32
static int ftp_syslog_level = DEFAULT_FTP_SYSLOG_LEVEL;
#endif
#endif

#define DEFAULT_LOG_FILENAME "ftp.log"

#define MODULE_NAME "LogFtpLog"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

TmEcode LogFtpLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFtpLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFtpLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogFtpLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogFtpLogThreadDeinit(ThreadVars *, void *);
void LogFtpLogExitPrintStats(ThreadVars *, void *);
static void LogFtpLogDeInitCtx(OutputCtx *);

void TmModuleLogFtpLogRegister (void) {
    tmm_modules[TMM_LOGFTPLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGFTPLOG].ThreadInit = LogFtpLogThreadInit;
    tmm_modules[TMM_LOGFTPLOG].Func = LogFtpLog;
    tmm_modules[TMM_LOGFTPLOG].ThreadExitPrintStats = LogFtpLogExitPrintStats;
    tmm_modules[TMM_LOGFTPLOG].ThreadDeinit = LogFtpLogThreadDeinit;
    tmm_modules[TMM_LOGFTPLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGFTPLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "ftp-log", LogFtpLogInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_FTP);
    SCLogInfo("registered %s", MODULE_NAME);
}

typedef struct LogFtpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogFtpFileCtx;

#define LOG_FTP_DEFAULT 0
#define LOG_FTP_JSON 1        /* JSON output */
#define LOG_FTP_JSON_SYSLOG 2 /* JSON output via syslog */

typedef struct LogFtpLogThread_ {
    LogFtpFileCtx *ftplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t ftp_cnt;

    MemBuffer *buffer;
} LogFtpLogThread;

static TmEcode LogFtpLogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    LogFtpLogThread *aft = (LogFtpLogThread *)data;
    LogFtpFileCtx *hlog = aft->ftplog_ctx;
    char timebuf[64];
    char *s = "";

    /* no flow, no smtp state */
    if (p->flow == NULL) {
        SCLogDebug("no flow");
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have FTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_FTP) {
        SCLogDebug("proto not ALPROTO_FTP: %u", proto);
        goto end;
    }
    FtpState *ftp_state = (FtpState *)AppLayerGetProtoStateFromPacket(p);
    if (ftp_state == NULL) {
        SCLogDebug("no smtp state, so no request logging");
        goto end;
    }
    if ((ftp_state->command != FTP_COMMAND_RETR) && 
        (ftp_state->command != FTP_COMMAND_STOR))
        goto end;

    if (ftp_state->line)
        s = strndup((char *)ftp_state->line, ftp_state->line_len);

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp, dp;
    if (!(PKT_IS_TOCLIENT(p))) {
        //SCLogInfo("FTP logger is TOCLIENT");
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
                goto fend;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        //SCLogInfo("FTP logger is TOSERVER");
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
                goto fend;
        }
        sp = p->dp;
        dp = p->sp;
    }

    /* reset */
    MemBufferReset(aft->buffer);

    json_t *js = json_object();
    if (js == NULL)
        goto fend;

    json_t *fjs = json_object();
    if (fjs == NULL) {
        free(js);
        goto fend;
    }

    /* time & tx */
    json_object_set_new(js, "time", json_string(timebuf));

    /* tuple */
    json_object_set_new(js, "srcip", json_string(srcip));
    json_object_set_new(js, "sp", json_integer(sp));
    json_object_set_new(js, "dstip", json_string(dstip));
    json_object_set_new(js, "dp", json_integer(dp));

    switch (ftp_state->command) {
        case FTP_COMMAND_RETR:
            json_object_set_new(fjs, "cmd", json_string("retr"));
            json_object_set_new(fjs, "arg", json_string(s));
            break;
        case FTP_COMMAND_STOR:
            json_object_set_new(fjs, "cmd", json_string("stor"));
            json_object_set_new(fjs, "arg", json_string(s));
            break;
        default:
            break;
    }
    if (ftp_state->line) free(s);

    /* smtp */
    json_object_set_new(js, "ftp", fjs);
    /*char **/s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
    MemBufferWriteString(aft->buffer, "%s", s);
    free(s);
    free(fjs);
    free(js);

    aft->ftp_cnt++;

    SCMutexLock(&hlog->file_ctx->fp_mutex);
#ifdef HAVE_LIBJANSSON
    if (hlog->flags & LOG_FTP_JSON_SYSLOG) {
        syslog(ftp_syslog_level, "%s", (char *)aft->buffer->buffer);
    } else {
        if (hlog->flags & LOG_FTP_JSON) {
            MemBufferWriteString(aft->buffer, "\n");
        }
#endif
        (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
        fflush(hlog->file_ctx->fp);
#ifdef HAVE_LIBJANSSON
    }
#endif
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);
fend:
    if (AppLayerTransactionUpdateLogId(ALPROTO_FTP, p->flow)) {
        ftp_state->command = FTP_COMMAND_UNKNOWN;

        if (ftp_state->line) {
            SCFree(ftp_state->line);
            ftp_state->line = NULL;
            ftp_state->line_len = 0;
        }
    }

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFtpLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogFtpLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogFtpLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogFtpLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogFtpLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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
        int r  = LogFtpLogIPv4(tv, p, data, pq, postpq);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = LogFtpLogIPv6(tv, p, data, pq, postpq);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogFtpLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogFtpLogThread *aft = SCMalloc(sizeof(LogFtpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogFtpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for DNSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->ftplog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogFtpLogThreadDeinit(ThreadVars *t, void *data)
{
    LogFtpLogThread *aft = (LogFtpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogFtpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogFtpLogExitPrintStats(ThreadVars *tv, void *data) {
    LogFtpLogThread *aft = (LogFtpLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("FTP logger logged %" PRIu32 " requests", aft->ftp_cnt);
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogFtpLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_FTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogFtpFileCtx *smtplog_ctx = SCMalloc(sizeof(LogFtpFileCtx));
    if (unlikely(smtplog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(smtplog_ctx, 0x00, sizeof(LogFtpFileCtx));

    smtplog_ctx->file_ctx = file_ctx;

#ifdef HAVE_LIBJANSSON
    const char *json = ConfNodeLookupChildValue(conf, "json");
    if (json) {
        if (strcmp(json, "syslog") == 0) {
            smtplog_ctx->flags |= (LOG_FTP_JSON | LOG_FTP_JSON_SYSLOG);
        } else if (ConfValIsTrue(json)) {
            smtplog_ctx->flags |= LOG_FTP_JSON;
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
    output_ctx->DeInit = LogFtpLogDeInitCtx;

    SCLogDebug("FTP log output initialized");

    return output_ctx;
}

static void LogFtpLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFtpFileCtx *smtplog_ctx = (LogFtpFileCtx *)output_ctx->data;
    LogFileFreeCtx(smtplog_ctx->file_ctx);
    SCFree(smtplog_ctx);
    SCFree(output_ctx);
}


